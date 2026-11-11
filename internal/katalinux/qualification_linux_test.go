//go:build linux && runnerd_qualification

package katalinux

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func labFixture(t *testing.T) (LabEnvelope, ed25519.PrivateKey, []byte, string) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(der)
	m := multiBlockFixture()
	m.Qualified = false
	m.Acceptance = nil
	now := time.Now().UTC()
	m.VerifiedAt = now.Add(-time.Minute).Format(time.RFC3339Nano)
	m.ExpiresAt = now.Add(time.Hour).Format(time.RFC3339Nano)
	name := "runnerd09-lab-unit"
	binding := LabBinding{CaseID: "unit", HostID: name, TenantID: name, PoolID: name, Repository: "Neticora/neticora-alpha", InstallationID: name, BootID: "unit-boot", MachineUUID: "unit-machine", ControlPlaneURL: "https://127.0.0.1:14443/api/v1/runner-hosts", ServiceUID: profile(m).Base.RunnerUID, DaemonConfigSHA256: strings.Repeat("a", 64), ObserverConfigSHA256: m.Files[m.ObserverConfig], PolicySHA256: strings.Repeat("b", 64), CapabilitiesSHA256: strings.Repeat("c", 64)}
	e := LabEnvelope{Version: LabEnvelopeVersion, Manifest: m, Binding: binding, IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(2 * time.Hour).Format(time.RFC3339Nano)}
	return e, key, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), hex.EncodeToString(sum[:])
}

func TestLabAuthorityNeverManufacturesAcceptance(t *testing.T) {
	e, key, pub, pin := labFixture(t)
	e, err := SignLabEnvelope(e, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(e)
	base := profile(e.Manifest)
	p, err := decodeLabProfile(raw, pub, pin, e.Binding, base.EvidenceDirectory, base.JournalDirectory, base.Base, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.Manifest.Qualified || len(p.Manifest.Acceptance) != 0 {
		t.Fatal("lab became completed qualification")
	}
	p.Manifest.GuestCapabilities = append(p.Manifest.GuestCapabilities, "SYS_PTRACE")
	if p.validate() == nil {
		t.Fatal("immutable lab profile mutated after signature")
	}
}

func TestNormalLoaderRejectsValidSignedLabAndAliases(t *testing.T) {
	e, key, pub, pin := labFixture(t)
	e, err := SignLabEnvelope(e, key)
	if err != nil {
		t.Fatal(err)
	}
	p := profile(e.Manifest)
	if err = ValidateLabPlan(e, pub, pin, p.EvidenceDirectory, p.JournalDirectory, p.Base); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	file, public := filepath.Join(dir, "profile.json"), filepath.Join(dir, "public.pem")
	raw, _ := json.Marshal(e)
	os.WriteFile(file, raw, 0600)
	os.WriteFile(public, pub, 0600)
	if _, err = Load(file, public, p.EvidenceDirectory, p.JournalDirectory, p.Base); err == nil {
		t.Fatal("normal loader accepted valid lab envelope")
	}
	alias := strings.Replace(string(raw), `"manifest":`, `"Manifest":`, 1)
	if _, err = decodeLabProfile([]byte(alias), pub, pin, e.Binding, p.EvidenceDirectory, p.JournalDirectory, p.Base, time.Now()); err == nil {
		t.Fatal("case alias bypassed original signed representation")
	}
	if _, err = decodeLabProfile(append(raw, []byte(` {}`)...), pub, pin, e.Binding, p.EvidenceDirectory, p.JournalDirectory, p.Base, time.Now()); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}

func TestLabAuthorityRejectsScopeTamperAndUnsafeBindings(t *testing.T) {
	for name, mutate := range map[string]func(*LabEnvelope){
		"production authority": func(e *LabEnvelope) { e.Manifest.Qualified = true },
		"fake acceptance": func(e *LabEnvelope) {
			e.Manifest.Acceptance = map[string]string{"original-01": "placeholder forbidden"}
		},
		"wrong host": func(e *LabEnvelope) { e.Binding.HostID = "another-host" },
		"public control plane": func(e *LabEnvelope) {
			e.Binding.ControlPlaneURL = "https://platform.scvcluster.neticora.com/api/v1/runner-hosts"
		},
		"HTTP":                   func(e *LabEnvelope) { e.Binding.ControlPlaneURL = "http://127.0.0.1:1234/api/v1/runner-hosts" },
		"future grant":           func(e *LabEnvelope) { e.IssuedAt = time.Now().Add(time.Hour).Format(time.RFC3339Nano) },
		"unbounded grant":        func(e *LabEnvelope) { e.ExpiresAt = time.Now().Add(8 * time.Hour).Format(time.RFC3339Nano) },
		"profile outlives grant": func(e *LabEnvelope) { e.Manifest.ExpiresAt = time.Now().Add(3 * time.Hour).Format(time.RFC3339Nano) },
		"unsafe storage":         func(e *LabEnvelope) { e.Manifest.Storage.Block.Transport = "virtio-fs" },
		"host capability": func(e *LabEnvelope) {
			e.Manifest.GuestCapabilities = append(e.Manifest.GuestCapabilities, "SYS_MODULE")
		},
	} {
		t.Run(name, func(t *testing.T) {
			e, key, pub, pin := labFixture(t)
			expected := e.Binding
			mutate(&e)
			signed, err := SignLabEnvelope(e, key)
			if err != nil {
				return
			}
			raw, _ := json.Marshal(signed)
			p := profile(e.Manifest)
			if _, err = decodeLabProfile(raw, pub, pin, expected, p.EvidenceDirectory, p.JournalDirectory, p.Base, time.Now()); err == nil {
				t.Fatal("unsafe lab grant accepted")
			}
		})
	}
	e, key, pub, pin := labFixture(t)
	e, _ = SignLabEnvelope(e, key)
	e.Manifest.HostKernel += "tamper"
	raw, _ := json.Marshal(e)
	p := profile(e.Manifest)
	if _, err := decodeLabProfile(raw, pub, pin, e.Binding, p.EvidenceDirectory, p.JournalDirectory, p.Base, time.Now()); err == nil {
		t.Fatal("unsigned modification accepted")
	}
	e, key, pub, _ = labFixture(t)
	e, _ = SignLabEnvelope(e, key)
	raw, _ = json.Marshal(e)
	if _, err := decodeLabProfile(raw, pub, strings.Repeat("0", 64), e.Binding, p.EvidenceDirectory, p.JournalDirectory, p.Base, time.Now()); err == nil {
		t.Fatal("wrong independent pin accepted")
	}
}

func TestExpiredLabAuthorityRemainsReadableForRecovery(t *testing.T) {
	e, key, pub, pin := labFixture(t)
	e.IssuedAt = time.Now().Add(-2 * time.Hour).Format(time.RFC3339Nano)
	e.ExpiresAt = time.Now().Add(-time.Hour).Format(time.RFC3339Nano)
	e.Manifest.ExpiresAt = e.ExpiresAt
	e, _ = SignLabEnvelope(e, key)
	raw, _ := json.Marshal(e)
	base := profile(e.Manifest)
	p, err := decodeLabProfile(raw, pub, pin, e.Binding, base.EvidenceDirectory, base.JournalDirectory, base.Base, time.Now())
	if err != nil {
		t.Fatal("expired cleanup authority became unreadable", err)
	}
	if p.Check(time.Now()) == nil {
		t.Fatal("expired authority admitted a new launch")
	}
}
