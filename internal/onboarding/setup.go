// Package onboarding adds durable local provisioning around the existing
// Runnerd04 proofs and bounded response recovery. It never enables execution.
package onboarding

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/identity"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

var ErrState = errors.New("setup state conflicts or is unsafe; preserve original files and inspect before retrying")

type Platform interface {
	Post(context.Context, string, string, protocol.Outbound, string) ([]byte, error)
	Installation(context.Context, string) (transport.InstallationBinding, error)
}
type Options struct {
	ConfigPath, SetupDir, StateDir, CredentialPath string
	PlatformURL, TenantID, PoolID, RuntimeEndpoint string
	// These are injected by the installed CLI, never accepted from the platform.
	BootID     string
	Probe      func(context.Context) (string, error)
	Token      func() ([]byte, error)
	Checkpoint func(string) error // In-process fault tests only; no CLI/environment override.
}
type attempt struct {
	PlatformURL     string `json:"platformUrl"`
	TenantID        string `json:"tenantId"`
	PoolID          string `json:"poolId"`
	RuntimeEndpoint string `json:"runtimeEndpoint"`
	RequestID       string `json:"requestId"`
	TokenHash       string `json:"tokenHash"`
	Fingerprint     string `json:"fingerprint"`
}

func nonce() (string, error) {
	var b [24]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func checkpoint(o Options, name string) error {
	if o.Checkpoint != nil {
		return o.Checkpoint(name)
	}
	return nil
}

// Create writes a new protected file and fsyncs both data and its directory.
// Link commits without replacement, so even a competing destination survives.
func Create(path string, data []byte) error {
	r, err := hostfs.OpenState(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer r.Close()
	n, err := nonce()
	if err != nil {
		return err
	}
	temp := ".setup-" + n
	f, err := r.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrState
	}
	defer r.Remove(temp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrState
	}
	if r.Link(temp, filepath.Base(path)) != nil {
		return ErrState
	}
	d, err := r.Open(".")
	if err != nil {
		return ErrState
	}
	defer d.Close()
	if d.Sync() != nil {
		return ErrState
	}
	return nil
}
func saveJSON(path string, value any) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return ErrState
	}
	defer clear(raw)
	return Create(path, raw)
}
func readJSON(path string, target any) error {
	raw, e := hostfs.ReadPrivate(path, 65536)
	if e != nil {
		return ErrState
	}
	defer clear(raw)
	if _, e = protocol.CanonicalizeJSON(raw); e != nil {
		return ErrState
	}
	// All callers also compare the complete persisted identity before acting.
	return json.Unmarshal(raw, target)
}
func exists(path string) (bool, error) {
	_, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return false, nil
	}
	return e == nil, e
}

func Setup(ctx context.Context, p Platform, o Options) (transport.InstallationBinding, error) {
	var zero transport.InstallationBinding
	base := config.Config{ControlPlaneURL: o.PlatformURL, StateDir: o.StateDir, CredentialFile: o.CredentialPath, RuntimeEndpoint: o.RuntimeEndpoint, RequestTimeoutSeconds: 15}
	raw, _ := json.Marshal(base)
	if _, e := config.Parse(raw); e != nil || o.TenantID == "" || o.PoolID == "" || o.Probe == nil || o.Token == nil {
		return zero, ErrState
	}
	root, e := hostfs.OpenState(o.SetupDir)
	if e != nil {
		return zero, e
	}
	defer root.Close()
	lock, e := hostfs.Lock(root)
	if e != nil {
		return zero, e
	}
	defer lock.Close()
	// Share the daemon's original installation lock, without opening/migrating SQLite.
	state, e := hostfs.OpenState(o.StateDir)
	if e != nil {
		return zero, e
	}
	defer state.Close()
	daemonLock, e := hostfs.Lock(state)
	if e != nil {
		return zero, e
	}
	defer daemonLock.Close()
	attemptPath := filepath.Join(o.SetupDir, "attempt.json")
	if present, err := exists(o.ConfigPath); err != nil {
		return zero, ErrState
	} else if present {
		data, err := hostfs.ReadPrivate(o.ConfigPath, config.MaxConfigBytes)
		if err != nil {
			return zero, err
		}
		old, err := config.Parse(data)
		if err != nil || old.Connection == nil || old.Execution != nil || old.ControlPlaneURL != base.ControlPlaneURL || old.StateDir != base.StateDir || old.CredentialFile != base.CredentialFile || old.RuntimeEndpoint != base.RuntimeEndpoint || old.Connection.TenantID != o.TenantID || old.Connection.RunnerDeploymentID != o.PoolID {
			return zero, ErrState
		}
	}
	present, e := exists(attemptPath)
	if e != nil {
		return zero, ErrState
	}
	// Existing execution histories and legacy identities must use their original
	// provisioning/recovery path; setup cannot rebind them as a fresh installation.
	if !present {
		for _, path := range []string{o.CredentialPath, filepath.Join(o.StateDir, "journal.sqlite"), filepath.Join(o.StateDir, "journal.db")} {
			if yes, err := exists(path); err != nil || yes {
				return zero, ErrState
			}
		}
		entries, err := os.ReadDir(o.StateDir)
		if err != nil {
			return zero, ErrState
		}
		for _, f := range entries {
			if f.Name() != "instance.lock" {
				return zero, ErrState
			}
		}
	}
	if e = checkpoint(o, "before-key"); e != nil {
		return zero, e
	}
	keyPath := filepath.Join(o.SetupDir, "original-key.seed")
	var seed []byte
	if yes, err := exists(keyPath); err != nil {
		return zero, ErrState
	} else if yes {
		seed, e = hostfs.ReadPrivate(keyPath, ed25519.SeedSize)
		if e != nil || len(seed) != ed25519.SeedSize {
			return zero, ErrState
		}
	} else {
		if present {
			return zero, ErrState
		}
		seed = make([]byte, ed25519.SeedSize)
		if _, e = rand.Read(seed); e != nil {
			return zero, e
		}
		if e = Create(keyPath, seed); e != nil {
			return zero, e
		}
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	pub, _ := x509.MarshalPKIXPublicKey(key.Public())
	fingerprint := digest(pub)
	if e = checkpoint(o, "after-key"); e != nil {
		return zero, e
	}
	var a attempt
	var token []byte
	defer func() { clear(token) }()
	if present {
		if readJSON(attemptPath, &a) != nil || a.PlatformURL != o.PlatformURL || a.TenantID != o.TenantID || a.PoolID != o.PoolID || a.RuntimeEndpoint != o.RuntimeEndpoint || a.Fingerprint != fingerprint || a.RequestID == "" || len(a.TokenHash) != 64 {
			return zero, ErrState
		}
	} else {
		token, e = o.Token()
		if e != nil {
			return zero, e
		}
		if len(token) < 16 || len(token) > 16384 {
			return zero, errors.New("invalid enrollment token")
		}
		request, e := nonce()
		if e != nil {
			return zero, e
		}
		a = attempt{o.PlatformURL, o.TenantID, o.PoolID, o.RuntimeEndpoint, request, digest(token), fingerprint}
		if e = saveJSON(attemptPath, a); e != nil {
			return zero, e
		}
	}
	if e = checkpoint(o, "after-attempt"); e != nil {
		return zero, e
	}
	responsePath := filepath.Join(o.SetupDir, "enrollment.json")
	var enrolled protocol.EnrollmentResponse
	if yes, err := exists(responsePath); err != nil {
		return zero, ErrState
	} else if yes {
		data, err := hostfs.ReadPrivate(responsePath, 65536)
		if err != nil || protocol.ValidateInboundJSON("EnrollmentResponse", data) != nil || json.Unmarshal(data, &enrolled) != nil {
			return zero, ErrState
		}
	} else {
		if len(token) == 0 {
			token, e = o.Token()
			if e != nil {
				return zero, e
			}
		}
		if digest(token) != a.TokenHash {
			return zero, errors.New("retry requires the original enrollment token; original attempt retained")
		}
		message, e := identity.Enrollment(key, a.RequestID, string(token))
		clear(token)
		if e != nil {
			return zero, e
		}
		data, e := p.Post(ctx, "/enroll", "", message, "EnrollmentResponse")
		if e != nil {
			return zero, e
		}
		if e = checkpoint(o, "after-enrollment-response"); e != nil {
			return zero, e
		}
		if protocol.ValidateInboundJSON("EnrollmentResponse", data) != nil || json.Unmarshal(data, &enrolled) != nil {
			return zero, ErrState
		}
		if e = Create(responsePath, data); e != nil {
			return zero, e
		}
	}
	access, e := Authenticate(ctx, p, key, enrolled.Identity, o.BootID)
	if e != nil {
		return zero, e
	}
	b, e := p.Installation(ctx, access)
	if e != nil {
		return zero, e
	}
	if b.Identity != enrolled.Identity || b.TenantID != a.TenantID || b.RunnerDeploymentID != a.PoolID || b.EnrollmentRequestID != a.RequestID || b.PublicKeyFingerprint != fingerprint {
		return zero, errors.New("authenticated installation binding does not match the original attempt")
	}
	endpoint, e := o.Probe(ctx)
	if e != nil || endpoint == "" {
		return zero, errors.New("Docker validation failed; original enrollment retained")
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	c := execution.Credentials{InstallationID: b.InstallationID, TenantID: b.TenantID, Identity: b.Identity, EndpointIdentity: endpoint, BootID: o.BootID, PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))}
	if yes, err := exists(o.CredentialPath); err != nil {
		return zero, ErrState
	} else if yes {
		old, k, err := execution.ReadCredentials(o.CredentialPath)
		defer clear(k)
		if err != nil || old.InstallationID != c.InstallationID || old.TenantID != c.TenantID || old.Identity != c.Identity || old.EndpointIdentity != c.EndpointIdentity || old.BootID != c.BootID || !bytes.Equal(k, key) {
			return zero, ErrState
		}
	} else {
		if e = checkpoint(o, "before-credentials"); e != nil {
			return zero, e
		}
		if e = saveJSON(o.CredentialPath, c); e != nil {
			return zero, e
		}
	}
	if e = checkpoint(o, "after-credentials"); e != nil {
		return zero, e
	}
	base.Connection = &config.Connection{TenantID: b.TenantID, RunnerDeploymentID: b.RunnerDeploymentID, EnrollmentRequestID: a.RequestID, PublicKeyFingerprint: fingerprint}
	if yes, err := exists(o.ConfigPath); err != nil {
		return zero, ErrState
	} else if !yes {
		if e = saveJSON(o.ConfigPath, base); e != nil {
			return zero, e
		}
	}
	if e = checkpoint(o, "after-config"); e != nil {
		return zero, e
	}
	return b, nil
}

func Authenticate(ctx context.Context, p Platform, key ed25519.PrivateKey, id protocol.HostIdentity, boot string) (string, error) {
	n, e := nonce()
	if e != nil {
		return "", e
	}
	m, e := identity.Assertion(key, id, boot, n, time.Now())
	if e != nil {
		return "", e
	}
	raw, e := p.Post(ctx, "/token", "", m, "TokenResponse")
	if e != nil {
		return "", e
	}
	response, e := protocol.DecodeTokenResponse(raw)
	if e != nil {
		return "", e
	}
	expiry, e := time.Parse(time.RFC3339Nano, response.ExpiresAt)
	if e != nil || !expiry.After(time.Now()) {
		return "", ErrState
	}
	return response.AccessToken, nil
}
