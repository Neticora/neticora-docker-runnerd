//go:build linux

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

const retirementEndpoint = "https://control.example/api/v1/runner-hosts"

func retirementFixture(t *testing.T) (string, *os.Root) {
	t.Helper()
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := hostfs.OpenState(state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	a := attempt{Endpoint: retirementEndpoint, TenantID: "tenant-1", RequestID: "request-1", BootID: "original-enrollment-boot", Seed: key.Seed(), Token: "CANARY-RETIRED-UI-TOKEN"}
	identity := protocol.HostIdentity{HostId: "host-1", KeyId: "key-1", KeyVersion: "1", SessionEpoch: "1"}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	credentials := execution.Credentials{InstallationID: "installation-1", TenantID: a.TenantID, EndpointIdentity: "docker-test-peer", Identity: identity, BootID: a.BootID, PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))}
	for name, value := range map[string]any{
		"attempt.json": a, "identity.json": credentials,
		"enrollment.json": map[string]any{"identity": identity, "protocol": map[string]string{"version": "1.0.0", "minimumRecoveryVersion": "1.0.0", "minimumAdmissionVersion": "1.0.0"}},
	} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = writeNew(root, name, raw); err != nil {
			t.Fatal(err)
		}
	}
	return state, root
}

func TestEnrollmentRetirementPreservesExportAndRetriesAfterMarkerCrash(t *testing.T) {
	for _, crashAfterMarker := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "marker-committed-before-unlink"}[crashAfterMarker], func(t *testing.T) {
			state, root := retirementFixture(t)
			identity, _ := os.ReadFile(filepath.Join(state, "identity.json"))
			receipt, _ := os.ReadFile(filepath.Join(state, "enrollment.json"))
			if crashAfterMarker {
				marker, err := validateRetirementExport(root, state, retirementEndpoint, "tenant-1", "installation-1")
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(marker)
				if err = writeNew(root, "retired.json", raw); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"--endpoint", retirementEndpoint, "--tenant-id", "tenant-1", "--state-dir", state, "--installation-id", "installation-1", "--retire-attempt", "--ca-file", "/missing/offline-ca", "--runtime-endpoint", "unix:///missing/offline-docker"}
			for i := 0; i < 2; i++ {
				if err := runArgs(args); err != nil {
					t.Fatal("offline retirement failed", err)
				}
			}
			if _, err := root.Lstat("attempt.json"); !os.IsNotExist(err) {
				t.Fatal("attempt still present", err)
			}
			for name, expected := range map[string][]byte{"identity.json": identity, "enrollment.json": receipt} {
				raw, err := os.ReadFile(filepath.Join(state, name))
				if err != nil || string(raw) != string(expected) {
					t.Fatal("retained export changed", name, err)
				}
			}
			marker, err := os.ReadFile(filepath.Join(state, "retired.json"))
			if err != nil || strings.Contains(string(marker), "CANARY") || strings.Contains(string(marker), "privateKeyPem") || strings.Contains(string(marker), `"seed"`) {
				t.Fatal("retirement marker contains secrets", err)
			}
			if err := runArgs([]string{"--endpoint", retirementEndpoint, "--tenant-id", "tenant-1", "--state-dir", state}); err == nil || !strings.Contains(err.Error(), "retired") {
				t.Fatal("retired state reenrolled", err)
			}
		})
	}
}

func TestEnrollmentRetirementRetainsSecretsOnUnverifiedExport(t *testing.T) {
	for _, fault := range []string{"missing-export", "different-key", "different-tenant", "receipt-mismatch", "marker-with-lost-export", "symlink-attempt"} {
		t.Run(fault, func(t *testing.T) {
			state, root := retirementFixture(t)
			if fault == "marker-with-lost-export" {
				marker, err := validateRetirementExport(root, state, retirementEndpoint, "tenant-1", "installation-1")
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(marker)
				if err = writeNew(root, "retired.json", raw); err != nil {
					t.Fatal(err)
				}
			}
			switch fault {
			case "missing-export", "marker-with-lost-export":
				os.Remove(filepath.Join(state, "identity.json"))
			case "different-key", "different-tenant":
				raw, _ := os.ReadFile(filepath.Join(state, "identity.json"))
				var c execution.Credentials
				json.Unmarshal(raw, &c)
				if fault == "different-key" {
					_, key, _ := ed25519.GenerateKey(rand.Reader)
					der, _ := x509.MarshalPKCS8PrivateKey(key)
					c.PrivateKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
				} else {
					c.TenantID = "another-tenant"
				}
				raw, _ = json.Marshal(c)
				os.WriteFile(filepath.Join(state, "identity.json"), raw, 0600)
			case "receipt-mismatch":
				raw, _ := os.ReadFile(filepath.Join(state, "enrollment.json"))
				os.WriteFile(filepath.Join(state, "enrollment.json"), []byte(strings.ReplaceAll(string(raw), "host-1", "host-2")), 0600)
			case "symlink-attempt":
				os.Rename(filepath.Join(state, "attempt.json"), filepath.Join(state, "keep-attempt.json"))
				os.Symlink("keep-attempt.json", filepath.Join(state, "attempt.json"))
			}
			if err := retireEnrollmentAttempt(state, retirementEndpoint, "tenant-1", "installation-1"); err == nil {
				t.Fatal("unsafe retirement accepted")
			}
			if _, err := root.Lstat("attempt.json"); err != nil {
				t.Fatal("recovery attempt removed", err)
			}
		})
	}
}
