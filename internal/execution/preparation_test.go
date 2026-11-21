package execution

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/config"
)

func TestPreparationNeverCreatesStateOrJournal(t *testing.T) {
	root := t.TempDir()
	c := config.Config{ControlPlaneURL: "https://example.invalid/hosts", StateDir: filepath.Join(root, "state"), RuntimeEndpoint: "unix:///run/absent-preparation.sock", CredentialFile: filepath.Join(root, "credentials.json"), RequestTimeoutSeconds: 15}
	c.Execution = &config.Execution{Enabled: false, Repository: "org/repo", Organization: "org", Pool: "pool", PolicyFile: filepath.Join(root, "policy"), CapabilitiesFile: filepath.Join(root, "caps"), ImageRepository: "registry/runner", NetworkID: "customer-network", BootstrapRoot: filepath.Join(root, "bootstrap"), KeysDirectory: filepath.Join(root, "keys"), TrustRoots: filepath.Join(root, "roots"), ImageBundles: filepath.Join(root, "bundles"), TrustProvisionedAt: "2026-11-15T00:00:00Z", PidsLimit: 128}
	raw, _ := json.Marshal(c)
	report := PrepareExecution(context.Background(), raw, time.Now())
	if report.ConfigurationValid || report.QualificationReady || report.AdmissionEnabled || report.WritesPerformed || report.JournalOpened {
		t.Fatalf("preparation granted authority: %+v", report)
	}
	if len(report.Checks) != 2 || report.Checks[0].State != "PASS" || report.Checks[1].Name != "identity" || report.Checks[1].State != "FAIL" {
		t.Fatalf("unexpected failure boundary: %+v", report.Checks)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("preparation wrote files: %v %v", entries, err)
	}
	c.Execution.Enabled = true
	raw, _ = json.Marshal(c)
	report = PrepareExecution(context.Background(), raw, time.Now())
	if len(report.Checks) != 1 || report.Checks[0].State != "FAIL" {
		t.Fatal("enabled controller candidate accepted")
	}
}
