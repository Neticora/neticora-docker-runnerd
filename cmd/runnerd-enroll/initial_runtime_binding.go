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
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/identity"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/initialbinding"
	"github.com/Neticora/neticora-docker-runnerd/journal"
	"github.com/Neticora/neticora-docker-runnerd/transport"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func refreshUnusedRuntime(endpoint, tenant, state, installation, observation, journalDir, issuerFile, caFile string) error {
	if os.Geteuid() == 0 || endpoint == "" || tenant == "" || state == "" || installation == "" || observation == "" || journalDir == "" || issuerFile == "" || state == journalDir {
		return initialbinding.ErrRejected
	}
	root, err := hostfs.OpenState(state)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := hostfs.Lock(root)
	if err != nil {
		return err
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := journal.OpenRecovery(ctx, journalDir, journal.Options{})
	if err != nil {
		return err
	}
	defer store.Close()
	if err = store.UnusedEnrollment(ctx); err != nil {
		return err
	}
	current, key, err := execution.ReadCredentials(filepath.Join(state, "identity.json"))
	if err != nil {
		return err
	}
	defer clear(key)
	if current.InstallationID != installation || current.TenantID != tenant || current.Identity.SessionEpoch != "1" || current.Identity.KeyVersion != "1" {
		return initialbinding.ErrRejected
	}
	boot, err := actualEnrollmentBoot()
	if err != nil || current.BootID != boot {
		return initialbinding.ErrRejected
	}
	target, err := readRuntimeObservation(observation, installation, tenant, current.Identity.HostId, boot)
	if err != nil {
		return err
	}
	receipt, err := hostfs.ReadPrivate(filepath.Join(state, "enrollment.json"), 65536)
	if err != nil {
		return err
	}
	var enrolled protocol.EnrollmentResponse
	if protocol.ValidateInboundJSON("EnrollmentResponse", receipt) != nil || json.Unmarshal(receipt, &enrolled) != nil || enrolled.Identity != current.Identity {
		return initialbinding.ErrRejected
	}
	originalPath := filepath.Join(state, "initial-runtime-original.json")
	originalRaw, err := hostfs.ReadPrivate(originalPath, 65536)
	if err != nil {
		if _, e := root.Lstat("initial-runtime-original.json"); !os.IsNotExist(e) {
			return initialbinding.ErrRejected
		}
		originalRaw, err = hostfs.ReadPrivate(filepath.Join(state, "identity.json"), 65536)
		if err != nil {
			return err
		}
		if err = writeNew(root, "initial-runtime-original.json", originalRaw); err != nil {
			return err
		}
	}
	defer clear(originalRaw)
	original, originalKey, err := execution.ReadCredentials(originalPath)
	if err != nil {
		return err
	}
	clear(originalKey)
	if original.PrivateKeyPEM != current.PrivateKeyPEM || original.Identity != current.Identity || original.BootID != boot || original.InstallationID != installation || original.TenantID != tenant || original.EndpointIdentity == target {
		return initialbinding.ErrRejected
	}
	var q initialbinding.Request
	requestRaw, err := hostfs.ReadPrivate(filepath.Join(state, "initial-runtime-request.json"), 16384)
	if err != nil {
		if _, e := root.Lstat("initial-runtime-request.json"); !os.IsNotExist(e) {
			return initialbinding.ErrRejected
		}
		var nonce [32]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return err
		}
		q = initialbinding.Request{Version: initialbinding.Version, BootID: boot, Nonce: hex.EncodeToString(nonce[:]), SourceCredentialHash: initialbinding.Hash(originalRaw), SourceEndpointIdentity: original.EndpointIdentity, TargetEndpointIdentity: target}
		requestRaw, _ = json.Marshal(q)
		if err = writeNew(root, "initial-runtime-request.json", requestRaw); err != nil {
			return err
		}
	} else {
		if _, err = protocol.CanonicalizeJSON(requestRaw); err != nil {
			return err
		}
		if json.Unmarshal(requestRaw, &q) != nil {
			return initialbinding.ErrRejected
		}
	}
	if q.BootID != boot || q.SourceCredentialHash != initialbinding.Hash(originalRaw) || q.SourceEndpointIdentity != original.EndpointIdentity || q.TargetEndpointIdentity != target {
		return initialbinding.ErrRejected
	}
	var ca []byte
	if caFile != "" {
		ca, err = hostfs.ReadPrivate(caFile, 1<<20)
		if err != nil {
			return err
		}
	}
	client, err := transport.NewWithRoots(endpoint, 15*time.Second, ca)
	if err != nil {
		return err
	}
	defer client.Close()
	var nonce [24]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	assertion, err := identity.Assertion(key, current.Identity, boot, hex.EncodeToString(nonce[:]), time.Now())
	if err != nil {
		return err
	}
	accessRaw, err := client.Post(ctx, "/token", "", assertion, "TokenResponse")
	if err != nil {
		return err
	}
	defer clear(accessRaw)
	var access protocol.TokenResponse
	if json.Unmarshal(accessRaw, &access) != nil {
		return initialbinding.ErrRejected
	}
	certificate, err := client.InitialRuntimeBinding(ctx, access.AccessToken, requestRaw)
	if err != nil {
		return err
	}
	public, err := hostfs.ReadPrivate(issuerFile, 16384)
	if err != nil {
		return err
	}
	block, rest := pem.Decode(public)
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return initialbinding.ErrRejected
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return initialbinding.ErrRejected
	}
	if _, err = initialbinding.Verify(certificate, q, installation, tenant, current.Identity, pub, time.Now()); err != nil {
		return err
	}
	if err = writeNew(root, "initial-runtime-certificate.json", certificate); err != nil {
		previous, e := hostfs.ReadPrivate(filepath.Join(state, "initial-runtime-certificate.json"), 16384)
		before, e1 := protocol.CanonicalizeJSON(previous)
		after, e2 := protocol.CanonicalizeJSON(certificate)
		if e != nil || e1 != nil || e2 != nil || string(before) != string(after) {
			return initialbinding.ErrRejected
		}
	}
	if current.EndpointIdentity != target {
		actual, e := hostfs.ReadPrivate(filepath.Join(state, "identity.json"), 65536)
		if e != nil {
			return e
		}
		defer clear(actual)
		if initialbinding.Hash(actual) != q.SourceCredentialHash {
			return initialbinding.ErrRejected
		}
		var document map[string]json.RawMessage
		if json.Unmarshal(actual, &document) != nil {
			return initialbinding.ErrRejected
		}
		document["endpointIdentity"], _ = json.Marshal(target)
		next, _ := json.Marshal(document)
		defer clear(next)
		if err = writeNew(root, "initial-runtime-next.json", next); err != nil {
			previous, e := hostfs.ReadPrivate(filepath.Join(state, "initial-runtime-next.json"), 65536)
			defer clear(previous)
			if e != nil || string(previous) != string(next) {
				return initialbinding.ErrRejected
			}
		}
		if err = root.Rename("initial-runtime-next.json", "identity.json"); err != nil {
			return err
		}
		parent, e := os.Open(state)
		if e != nil {
			return e
		}
		err = parent.Sync()
		parent.Close()
		if err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"hostId": current.Identity.HostId, "sessionEpoch": current.Identity.SessionEpoch, "originalKeyRetained": true, "initialRuntimeBindingApplied": true, "executionAuthorityGranted": false})
}

func actualEnrollmentBoot() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(raw))
	if len(v) != 36 {
		return "", errors.New("current boot unavailable")
	}
	return v, nil
}
