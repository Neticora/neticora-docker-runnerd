package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

type retirementRecord struct {
	Version        string `json:"version"`
	Endpoint       string `json:"endpoint"`
	TenantID       string `json:"tenantId"`
	InstallationID string `json:"installationId"`
	AttemptHash    string `json:"attemptSha256"`
	ReceiptHash    string `json:"receiptSha256"`
	IdentityHash   string `json:"identitySha256"`
}

func retirementHash(raw []byte) string {
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func validateRetirementExport(root *os.Root, state, endpoint, tenant, installation string) (retirementRecord, error) {
	r := retirementRecord{Version: "runnerd-enrollment-retired-v1", Endpoint: strings.TrimRight(endpoint, "/"), TenantID: tenant, InstallationID: installation}
	raw, err := hostfs.ReadPrivate(filepath.Join(state, "attempt.json"), 65536)
	if err != nil {
		return r, errors.New("protected enrollment attempt required; retain state")
	}
	defer clear(raw)
	var a attempt
	if _, err = protocol.CanonicalizeJSON(raw); err != nil || json.Unmarshal(raw, &a) != nil {
		return r, errors.New("invalid enrollment attempt; retain state")
	}
	defer clear(a.Seed)
	if a.Endpoint != r.Endpoint || a.TenantID != tenant || len(a.Seed) != ed25519.SeedSize {
		return r, errors.New("enrollment retirement scope mismatch; retain state")
	}
	receipt, err := hostfs.ReadPrivate(filepath.Join(state, "enrollment.json"), 65536)
	var enrolled protocol.EnrollmentResponse
	if err != nil || protocol.ValidateInboundJSON("EnrollmentResponse", receipt) != nil || json.Unmarshal(receipt, &enrolled) != nil {
		return r, errors.New("confirmed enrollment receipt required; retain state")
	}
	credentials, key, err := execution.ReadCredentials(filepath.Join(state, "identity.json"))
	if err != nil {
		return r, errors.New("valid exported credentials required; retain enrollment recovery secrets")
	}
	defer clear(key)
	expected := ed25519.NewKeyFromSeed(a.Seed)
	defer clear(expected)
	if credentials.InstallationID != installation || credentials.TenantID != tenant || credentials.BootID != a.BootID || credentials.Identity != enrolled.Identity || !expected.Public().(ed25519.PublicKey).Equal(key.Public()) {
		return r, errors.New("export does not match enrollment key/identity/scope; retain state")
	}
	identity, err := hostfs.ReadPrivate(filepath.Join(state, "identity.json"), 65536)
	if err != nil {
		return r, err
	}
	defer clear(identity)
	// ReadCredentials deliberately clears the PEM field after parsing. Restore
	// the canonical export representation only for the snapshot equality check.
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return r, err
	}
	defer clear(der)
	encodedPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(encodedPEM)
	credentials.PrivateKeyPEM = string(encodedPEM)
	encoded, err := json.Marshal(credentials)
	if err != nil {
		return r, err
	}
	defer clear(encoded)
	left, e1 := protocol.CanonicalizeJSON(identity)
	right, e2 := protocol.CanonicalizeJSON(encoded)
	defer clear(left)
	defer clear(right)
	if e1 != nil || e2 != nil || !bytes.Equal(left, right) {
		return r, errors.New("credential export changed during retirement; retain state")
	}
	// Ensure the verified export and its directory are durable before committing
	// a secret-free retirement marker. No network or Docker access is needed.
	f, err := root.Open("identity.json")
	if err != nil {
		return r, err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return r, errors.Join(err, closeErr)
	}
	r.AttemptHash, r.ReceiptHash, r.IdentityHash = retirementHash(raw), retirementHash(receipt), retirementHash(identity)
	return r, nil
}

// Commit the sanitized marker before unlinking the one known attempt. A crash
// at either boundary is retryable; never regenerate or overwrite a host key.
func retireEnrollmentAttempt(state, endpoint, tenant, installation string) error {
	if installation == "" {
		return errors.New("retirement requires the independently verified --installation-id")
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
	raw, err := hostfs.ReadPrivate(filepath.Join(state, "retired.json"), 4096)
	var marker retirementRecord
	if err == nil {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		_, canonicalErr := protocol.CanonicalizeJSON(raw)
		if canonicalErr != nil || decoder.Decode(&marker) != nil || marker.Version != "runnerd-enrollment-retired-v1" || marker.Endpoint != strings.TrimRight(endpoint, "/") || marker.TenantID != tenant || marker.InstallationID != installation {
			return errors.New("invalid or mismatched retirement marker; retain state")
		}
		for _, hash := range []string{marker.AttemptHash, marker.ReceiptHash, marker.IdentityHash} {
			decoded, e := hex.DecodeString(hash)
			if e != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != hash {
				return errors.New("invalid retirement audit hashes; retain state")
			}
		}
	} else {
		if _, statErr := root.Lstat("retired.json"); !errors.Is(statErr, os.ErrNotExist) {
			return errors.New("unsafe retirement marker; retain state")
		}
		marker, err = validateRetirementExport(root, state, endpoint, tenant, installation)
		if err != nil {
			return err
		}
		data, err := json.Marshal(marker)
		if err != nil {
			return err
		}
		if err = writeNew(root, "retired.json", data); err != nil {
			return errors.New("retirement marker not confirmed durable; retain state and retry")
		}
	}
	attemptRaw, err := hostfs.ReadPrivate(filepath.Join(state, "attempt.json"), 65536)
	defer clear(attemptRaw)
	if err == nil {
		if retirementHash(attemptRaw) != marker.AttemptHash {
			return errors.New("attempt changed after retirement marker; retain state")
		}
		// Marker existence alone cannot prove the previous directory fsync
		// completed. Revalidate/fsync the export before finishing an interrupted
		// retirement, and retain secrets if anything no longer matches.
		verified, err := validateRetirementExport(root, state, endpoint, tenant, installation)
		if err != nil || verified != marker {
			return errors.New("retirement export no longer verified; retain state")
		}
		if err = syncRetirementDirectory(root); err != nil {
			return err
		}
		if err = root.Remove("attempt.json"); err != nil {
			return err
		}
	} else if _, statErr := root.Lstat("attempt.json"); !errors.Is(statErr, os.ErrNotExist) {
		return errors.New("unsafe attempt during retirement; retain state")
	}
	return syncRetirementDirectory(root)
}

func syncRetirementDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
