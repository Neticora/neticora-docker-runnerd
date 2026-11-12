//go:build linux

package katalinux

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

func brokerOriginFixture(t *testing.T) (*Profile, json.RawMessage) {
	t.Helper()
	p := profile(multiBlockFixture())
	p.brokerOwned = true
	p.EvidenceDirectory = t.TempDir()
	p.JournalDirectory = t.TempDir()
	authorityDirectory := t.TempDir()
	for _, directory := range []string{p.EvidenceDirectory, p.JournalDirectory, authorityDirectory} {
		if err := os.Chmod(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	p.storageAuthority = filepath.Join(authorityDirectory, "original-authority.pem")
	if err := os.WriteFile(p.storageAuthority, []byte("original public authority"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := p.BrokerOrigin()
	if err != nil {
		t.Fatal(err)
	}
	return p, raw
}
func TestBrokerCleanupOriginCannotBecomeLaunchProfile(t *testing.T) {
	p, raw := brokerOriginFixture(t)
	restored, err := RestoreBrokerCleanup(raw, p.Base, "installation", "host")
	if err != nil {
		t.Fatal(err)
	}
	if !restored.cleanupOnly || string(restored.storageAuthorityPEM) != "original public authority" {
		t.Fatal("lost original cleanup authority")
	}
	spec := protocol.ExecutionSpec{ExecutionId: "execution", AttemptId: "attempt", Generation: "1", SpecHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", IsolationProfile: "isolated", ProfileVersion: p.ID, TemplateVersion: BlockTemplate, ImageDigest: p.Manifest.ImageDigest, Resources: p.Manifest.Budget.Effective}
	scope := agent.StoreScope{InstallationID: "installation", TenantID: "tenant", HostID: "host", EndpointIdentity: p.Manifest.EndpointIdentity}
	original, err := p.RecoveryPlan(scope, spec)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restored.RecoveryPlan(scope, spec)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(original)
	b, _ := json.Marshal(recovered)
	if string(a) != string(b) || !recovered.RecoveryOnly {
		t.Fatal("historical plan replaced")
	}
	if restored.RequireLaunchStorage() == nil {
		t.Fatal("cleanup profile authorized allocation")
	}
	if _, err = restored.Plan(scope, spec); err == nil {
		t.Fatal("cleanup profile authorized new work")
	}
}
func TestBrokerCleanupRejectsChangedOriginalDirectoryOrManifest(t *testing.T) {
	for _, name := range []string{"missing", "profile", "evidence", "journal", "uid", "symlink", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			p, raw := brokerOriginFixture(t)
			var origin BrokerOrigin
			if json.Unmarshal(raw, &origin) != nil {
				t.Fatal("fixture")
			}
			switch name {
			case "missing":
				raw = nil
			case "profile":
				origin.Manifest.RuntimeSelector = "replacement-runtime"
			case "evidence":
				origin.EvidenceInode++
			case "journal":
				origin.JournalInode++
			case "uid":
				origin.JournalUID++
			case "symlink":
				link := filepath.Join(t.TempDir(), "journal")
				if err := os.Symlink(p.JournalDirectory, link); err != nil {
					t.Fatal(err)
				}
				origin.JournalDirectory = link
			case "duplicate":
				raw = append([]byte(`{"version":"duplicate",`), raw[1:]...)
			}
			if name != "missing" && name != "duplicate" {
				raw, _ = json.Marshal(origin)
			}
			if _, err := RestoreBrokerCleanup(raw, p.Base, "installation", "host"); err == nil {
				t.Fatal("historical ownership adopted")
			}
		})
	}
}

func TestBootDeviceAbsenceRequiresChangedBootAndProtectedTmpfs(t *testing.T) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct{ path, boot string }{
		{"/run/neticora-missing-recovery-test/devices", ""},
		{"/run/neticora-missing-recovery-test/devices", strings.TrimSpace(string(boot))},
		{"/var/lib/neticora-missing-recovery-test/devices", "other-boot"},
		{"/run/../tmp/neticora-missing-recovery-test/devices", "other-boot"},
	} {
		if verifyBootTmpfsAbsence(v.path, v.boot) == nil {
			t.Fatal("unverified node absence accepted", v)
		}
	}
}
