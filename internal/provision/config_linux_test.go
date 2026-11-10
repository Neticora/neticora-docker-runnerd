//go:build linux

package provision

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
)

func fixture() Bundle {
	return Bundle{Version: "runnerd09-config-bundle-v1", Daemon: config.Config{ControlPlaneURL: "https://control.example.invalid/api/v1/runner-hosts", StateDir: "/var/lib/neticora-runnerd", RuntimeEndpoint: "unix:///run/test-docker.sock", CredentialFile: "/etc/neticora-runnerd/identity.json", RequestTimeoutSeconds: 15, Execution: &config.Execution{Enabled: true, Repository: "Neticora/neticora-alpha", PolicyFile: "/etc/neticora-runnerd/policy.json", CapabilitiesFile: "/etc/neticora-runnerd/capabilities.json", ImageRepository: "example/runner", NetworkID: strings.Repeat("a", 64), BootstrapRoot: "/run/neticora-bootstrap", KeysDirectory: "/var/lib/neticora-runnerd-keys", TrustRoots: "/etc/neticora-runnerd/roots", ImageBundles: "/etc/neticora-runnerd/bundles", TrustProvisionedAt: "2026-11-09T00:00:00Z", Organization: "Neticora", Pool: "pool", PidsLimit: 512, Kata: &config.Kata{ObserverSocket: "/run/observer/observer.sock", ProfileFile: "/etc/neticora-runnerd/profile.json", PublicKeyFile: "/etc/neticora-runnerd/public.pem", EvidenceDirectory: "/var/lib/observer"}}}, Observer: katalinux.ObserverConfig{Socket: "/run/observer/observer.sock", ServiceUID: 10001, ProfileDirectory: "/etc/observer/profiles", PublicKeyFile: "/etc/observer/public.pem", EvidenceDirectory: "/var/lib/observer", JournalDirectory: "/var/lib/neticora-runnerd", RuntimeEndpoint: "unix:///run/test-docker.sock", InstallationID: "installation", HostID: "host", NetworkID: strings.Repeat("a", 64), BootstrapRoot: "/run/neticora-bootstrap", PidsLimit: 512}}
}
func TestBundleRejectsCrossRoleMismatchAndExposedTrust(t *testing.T) {
	for name, mutate := range map[string]func(*Bundle){"network": func(b *Bundle) { b.Observer.NetworkID = strings.Repeat("b", 64) }, "journal": func(b *Bundle) { b.Observer.JournalDirectory = "/other" }, "socket": func(b *Bundle) { b.Observer.Socket = "/other.sock" }, "same ownership file": func(b *Bundle) { b.Observer.PublicKeyFile = b.Daemon.Execution.Kata.PublicKeyFile }, "exposed root trust": func(b *Bundle) { b.Observer.PublicKeyFile = b.Observer.BootstrapRoot + "/key.pem" }, "nonroot observer path": func(b *Bundle) { b.Observer.ProfileDirectory = "relative" }} {
		t.Run(name, func(t *testing.T) {
			b := fixture()
			mutate(&b)
			raw, _ := json.Marshal(b)
			if _, err := Parse(raw); err == nil {
				t.Fatal("incoherent bundle accepted")
			}
		})
	}
	if _, err := Parse([]byte(`{"version":"x","version":"runnerd09-config-bundle-v1"}`)); err == nil {
		t.Fatal("duplicate keys accepted")
	}
	b := fixture()
	b.Daemon.Execution.PolicyFile = b.Daemon.CredentialFile
	raw, _ := json.Marshal(b)
	if _, err := Parse(raw); err == nil {
		t.Fatal("policy overwrites identity")
	}
	b = fixture()
	b.Observer.ProfileDirectory = filepath.Dir(b.Daemon.Execution.Kata.ProfileFile)
	raw, _ = json.Marshal(b)
	if _, err := Parse(raw); err == nil {
		t.Fatal("service trust placed in root-only profile directory")
	}
}
func TestBundleDurablePrivateOutputAndNoOverwrite(t *testing.T) {
	b := fixture()
	raw, _ := json.Marshal(b)
	if _, err := Parse(raw); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	os.Chmod(parent, 0700)
	output := filepath.Join(parent, "bundle")
	receipt, err := Write(output, b)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ArtifactsVerified || receipt.AdmissionChanged || len(receipt.Artifacts) != 2 {
		t.Fatal("rendering claimed qualification")
	}
	for _, name := range []string{"daemon.json", "observer.json", "receipt.json"} {
		info, err := os.Lstat(filepath.Join(output, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("unprotected output", name)
		}
	}
	before, _ := os.ReadFile(filepath.Join(output, "daemon.json"))
	if _, err = Write(output, b); err == nil {
		t.Fatal("existing bundle reused")
	}
	after, _ := os.ReadFile(filepath.Join(output, "daemon.json"))
	if string(before) != string(after) {
		t.Fatal("existing config replaced")
	}
	link := filepath.Join(parent, "dangling")
	os.Symlink(filepath.Join(parent, "missing"), link)
	if _, err = Write(link, b); err == nil {
		t.Fatal("dangling output symlink accepted")
	}
}
