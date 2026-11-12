//go:build linux && runnerd_broker_qualification && runnerd_qualification

package execution

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/Neticora/neticora-docker-runnerd/internal/broker"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Self-issued qualification fixtures, never production Signed artifacts. The
// seed supplies existing physical storage roots; all original ownership remains.
func phaseEKataSpec(t *testing.T, spec map[string]any, identity string) (json.RawMessage, string) {
	seed := os.Getenv("RUNNERD_PHASE_E_SEED")
	if seed == "" {
		return nil, ""
	}
	raw, err := os.ReadFile(seed)
	if err != nil {
		t.Fatal(err)
	}
	var envelope katalinux.LabEnvelope
	if json.Unmarshal(raw, &envelope) != nil || envelope.Manifest.Qualified || len(envelope.Manifest.Acceptance) != 0 || envelope.Manifest.Version != katalinux.MultiBlockVersion || envelope.Manifest.Storage.Block == nil {
		t.Fatal("explicit unqualified block-backed lab seed required")
	}
	m := envelope.Manifest
	// Requalification observes this boot's actual mounted pool, not a fabricated
	// storage reconciliation or a rewrite of any prior allocation.
	var st syscall.Stat_t
	if syscall.Stat(m.Storage.Block.Pool.Root, &st) != nil {
		t.Fatal("pool missing")
	}
	m.Storage.Block.Pool.Device = uint64(st.Dev)
	bootKernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatal(err)
	}
	m.HostKernel = strings.TrimSpace(string(bootKernel))
	now := time.Now().UTC()
	m.VerifiedAt = now.Format(wireTime)
	m.ExpiresAt = now.Add(30 * time.Minute).Format(wireTime)
	// Endpoint is replaced only in this new unqualified manifest, never history.
	m.EndpointIdentity = identity
	if m.EndpointIdentity == "" {
		t.Fatal("independently probed endpoint identity required")
	}
	id, err := katalinux.ProfileID(m)
	if err != nil {
		t.Fatal(err)
	}
	spec["isolationProfile"] = "isolated"
	spec["dockerBuild"] = true
	spec["templateVersion"] = katalinux.BlockTemplate
	spec["profileVersion"] = id
	spec["imageDigest"] = m.ImageDigest
	spec["resources"] = m.Budget.Effective
	return phaseDJSON(m), id
}
func phaseEKataBroker(t *testing.T, c *broker.Config, raw json.RawMessage, policy []byte, url string) {
	var m katalinux.Manifest
	if json.Unmarshal(raw, &m) != nil {
		t.Fatal("manifest")
	}
	// Exact original directories are mandatory: changing them causes pool owner
	// validation to fail, even when the slot index appears empty.
	ownerRaw, err := os.ReadFile(filepath.Join(m.Storage.Block.Pool.Root, ".runnerd.owner.json"))
	if err != nil {
		t.Fatal(err)
	}
	var owner struct {
		Record struct{ EvidenceDirectory, JournalDirectory string }
	}
	if json.Unmarshal(ownerRaw, &owner) != nil || owner.Record.EvidenceDirectory == "" {
		t.Fatal("pool owner")
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	pin := sha256.Sum256(der)
	profilePath := filepath.Join(filepath.Dir(c.Runtime.PolicyFile), "kata-profile.json")
	publicPath := filepath.Join(filepath.Dir(c.Runtime.PolicyFile), "kata-public.pem")
	phaseDWrite(t, publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600, 0)
	boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	uuid, _ := os.ReadFile("/sys/class/dmi/id/product_uuid")
	caseID := strings.TrimPrefix(c.Scope.InstallationID, "runnerd09-lab-")
	b := katalinux.LabBinding{CaseID: caseID, InstallationID: c.Scope.InstallationID, HostID: c.Scope.HostID, TenantID: c.Scope.TenantID, PoolID: c.Scope.InstallationID, Repository: c.Runtime.Repository, BootID: strings.TrimSpace(string(boot)), MachineUUID: strings.TrimSpace(string(uuid)), ControlPlaneURL: url + "/api/v1/runner-hosts", ServiceUID: int(c.ControllerUID), DaemonConfigSHA256: phaseDHash(c), ObserverConfigSHA256: m.Files[m.ObserverConfig], PolicySHA256: phaseDHash(json.RawMessage(policy)), CapabilitiesSHA256: phaseDHash(m)}
	now := time.Now().UTC()
	envelope, err := katalinux.SignLabEnvelope(katalinux.LabEnvelope{Version: katalinux.LabEnvelopeVersion, Binding: b, Manifest: m, IssuedAt: now.Format(wireTime), ExpiresAt: now.Add(time.Hour).Format(wireTime)}, key)
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	phaseDWrite(t, profilePath, phaseDJSON(envelope), 0600, 0)
	c.Runtime.Kata = &broker.KataConfig{ProfileFile: profilePath, PublicKeyFile: publicPath, EvidenceDirectory: owner.Record.EvidenceDirectory, JournalDirectory: owner.Record.JournalDirectory, QualificationPin: hex.EncodeToString(pin[:])}
	t.Log("unqualified lab tuple fixture; original pool/evidence/journal ownership preserved; production admission false")
}
func phaseEKataController(t *testing.T, c *Controller, p phaseDPublic) {
	if p.KataProfileID == "" {
		return
	}
	var m katalinux.Manifest
	if json.Unmarshal(p.KataManifest, &m) != nil {
		t.Fatal("manifest")
	}
	c.Kata = &katalinux.Profile{ID: p.KataProfileID, Manifest: m, Base: c.Profile, EvidenceDirectory: p.KataEvidenceDirectory, JournalDirectory: p.KataJournalDirectory}
}
