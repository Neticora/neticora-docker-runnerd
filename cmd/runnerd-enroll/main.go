// runnerd-enroll persists an enrollment attempt before contacting the platform.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/identity"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

type attempt struct {
	Endpoint  string `json:"endpoint"`
	TenantID  string `json:"tenantId"`
	RequestID string `json:"requestId"`
	BootID    string `json:"bootId"`
	Seed      []byte `json:"seed"`
	Token     string `json:"token"`
}

func main() {
	if err := run(); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error { return runArgs(os.Args[1:]) }
func runArgs(args []string) error {
	flags := flag.NewFlagSet("runnerd-enroll", flag.ContinueOnError)
	caFile := flags.String("ca-file", "", "optional protected PEM CA file; certificate verification remains enabled")
	endpoint := flags.String("endpoint", "", "HTTPS runner-host API URL, ending /api/v1/runner-hosts")
	tenant := flags.String("tenant-id", "", "canonical tenant UUID supplied by the operator")
	state := flags.String("state-dir", "", "existing service-owned 0700 enrollment directory, separate from journal")
	token := flags.String("token-file", "", "owner-only 0600 file containing the UI enrollment token; first attempt only")
	installation := flags.String("installation-id", "", "independently verified platform installation ID; enables credential export")
	runtime := flags.String("runtime-endpoint", "unix:///run/docker.sock", "local Docker socket for read-only identity probe")
	retire := flags.Bool("retire-attempt", false, "offline: retire the token/seed attempt after verifying durable credential export; retain identity and receipt")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *endpoint == "" || *tenant == "" || *state == "" {
		return errors.New("usage: runnerd-enroll --endpoint HTTPS_URL --tenant-id UUID --state-dir PATH [--token-file PATH] [--installation-id ID --runtime-endpoint unix:///run/docker.sock | --installation-id ID --retire-attempt]")
	}
	if *retire {
		if err := retireEnrollmentAttempt(*state, *endpoint, *tenant, *installation); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"attemptRetired": true, "identityAndReceiptDeletedByCommand": false, "admissionEnabledByCommand": false})
	}
	var roots []byte
	if *caFile != "" {
		var e error
		roots, e = hostfs.ReadPrivate(*caFile, 1<<20)
		if e != nil {
			return e
		}
	}
	client, err := transport.NewWithRoots(*endpoint, 15*time.Second, roots)
	if err != nil {
		return err
	}
	defer client.Close()
	root, err := hostfs.OpenState(*state)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := hostfs.Lock(root)
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := root.Lstat("retired.json"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("enrollment attempt retired or retirement marker unreadable; use the retained identity, never reenroll this state directory")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return errors.New("Linux boot identity unavailable")
	}
	var a attempt
	raw, err := hostfs.ReadPrivate(filepath.Join(*state, "attempt.json"), 65536)
	if err != nil {
		if _, statErr := root.Lstat("attempt.json"); !errors.Is(statErr, os.ErrNotExist) {
			return errors.New("unsafe or unreadable enrollment attempt; retain state")
		}
		if _, statErr := root.Lstat("enrollment.json"); !errors.Is(statErr, os.ErrNotExist) {
			return errors.New("receipt without attempt; retain state")
		}
		if *token == "" {
			return errors.New("first enrollment requires --token-file; retries reuse persisted state")
		}
		t, e := hostfs.ReadPrivate(*token, 16384)
		if e != nil {
			return e
		}
		defer clear(t)
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		defer clear(key)
		var nonce [24]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			return e
		}
		a = attempt{Endpoint: strings.TrimRight(*endpoint, "/"), TenantID: *tenant, RequestID: hex.EncodeToString(nonce[:]), BootID: strings.TrimSpace(string(boot)), Seed: key.Seed(), Token: strings.TrimSpace(string(t))}
		if _, e = identity.Enrollment(key, a.RequestID, a.Token); e != nil {
			return errors.New("invalid enrollment input")
		}
		raw, e = json.Marshal(a)
		if e != nil {
			return e
		}
		if e = writeNew(root, "attempt.json", raw); e != nil {
			return e
		}
	} else {
		if json.Unmarshal(raw, &a) != nil {
			return errors.New("invalid enrollment attempt; retain state")
		}
	}
	defer clear(raw)
	defer clear(a.Seed)
	if a.Endpoint != strings.TrimRight(*endpoint, "/") || a.TenantID != *tenant || len(a.Seed) != ed25519.SeedSize || a.BootID != strings.TrimSpace(string(boot)) {
		return errors.New("enrollment scope or boot changed; explicit operator recovery required")
	}
	key := ed25519.NewKeyFromSeed(a.Seed)
	defer clear(key)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var enrolled protocol.EnrollmentResponse
	receipt, e := hostfs.ReadPrivate(filepath.Join(*state, "enrollment.json"), 65536)
	if e != nil {
		if _, statErr := root.Lstat("enrollment.json"); !errors.Is(statErr, os.ErrNotExist) {
			return errors.New("unsafe enrollment receipt; retain state")
		}
		request, e := identity.Enrollment(key, a.RequestID, a.Token)
		if e != nil {
			return e
		}
		receipt, e = client.Post(ctx, "/enroll", "", request, "EnrollmentResponse")
		if e != nil {
			return errors.New("enrollment not confirmed; rerun identical command with the same state directory, never generate a replacement key")
		}
		if json.Unmarshal(receipt, &enrolled) != nil {
			return errors.New("invalid enrollment response")
		}
		if e = writeNew(root, "enrollment.json", receipt); e != nil {
			return e
		}
	} else if protocol.ValidateInboundJSON("EnrollmentResponse", receipt) != nil || json.Unmarshal(receipt, &enrolled) != nil {
		return errors.New("invalid stored enrollment receipt")
	}

	var nonce [24]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	assertion, e := identity.Assertion(key, enrolled.Identity, a.BootID, hex.EncodeToString(nonce[:]), time.Now())
	if e != nil {
		return e
	}
	accessRaw, e := client.Post(ctx, "/token", "", assertion, "TokenResponse")
	if e != nil {
		return errors.New("enrollment retained; signed authentication failed")
	}
	defer clear(accessRaw)
	var access protocol.TokenResponse
	if json.Unmarshal(accessRaw, &access) != nil {
		return errors.New("invalid authentication response")
	}
	configuration, e := client.Config(ctx, access.AccessToken)
	if e != nil {
		return errors.New("enrollment retained; authenticated pool configuration unavailable")
	}
	var remote protocol.ConfigResponse
	if json.Unmarshal(configuration, &remote) != nil {
		return errors.New("invalid platform configuration")
	}
	if *installation != "" {
		engine, e := dockerengine.OpenReadOnly(*runtime, *installation, nil)
		if e != nil {
			return e
		}
		defer engine.Close()
		peer, e := engine.Probe(ctx)
		if e != nil {
			return errors.New("Docker identity probe failed; enrollment retained")
		}
		der, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return e
		}
		defer clear(der)
		credentials := execution.Credentials{InstallationID: *installation, TenantID: a.TenantID, EndpointIdentity: peer, Identity: enrolled.Identity, BootID: a.BootID, PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))}
		data, e := json.Marshal(credentials)
		if e != nil {
			return e
		}
		defer clear(data)
		if e = writeNew(root, "identity.json", data); e != nil {
			return errors.New("credential export refused; never overwrite an existing identity")
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"hostId": enrolled.Identity.HostId, "sessionEpoch": enrolled.Identity.SessionEpoch, "credentialsWritten": *installation != "", "platformAdmissionEnabled": remote.AdmissionEnabled, "authenticatedConfigVerified": true, "admissionEnabledByCommand": false})
}

// Exclusive creation and both fsyncs precede network use. Partial files are
// retained and rejected on retry, rather than silently replacing identity.
func writeNew(root *os.Root, name string, data []byte) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
