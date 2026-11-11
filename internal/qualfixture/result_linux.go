//go:build linux && runnerd_qualification

package qualfixture

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"strconv"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/provision"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

type ResultInput struct {
	Version       string                `json:"version"`
	Profile       katalinux.LabEnvelope `json:"profile"`
	Bundle        provision.Bundle      `json:"bundle"`
	LabPublicKey  string                `json:"labPublicKey"`
	FixtureConfig Config                `json:"fixtureConfig"`
	Fixture       State                 `json:"fixture"`
	Proof         json.RawMessage       `json:"proof"`
}

func ValidatePlanBundle(e katalinux.LabEnvelope, b provision.Bundle) error {
	x, binding := b.Daemon.Execution, e.Binding
	if x == nil || x.Kata == nil || b.Daemon.ControlPlaneURL != binding.ControlPlaneURL || x.Repository != binding.Repository || x.Pool != binding.PoolID || b.Observer.HostID != binding.HostID || b.Observer.InstallationID != binding.InstallationID || b.Observer.ServiceUID != binding.ServiceUID || e.Manifest.ObserverConfig != filepath.Join(filepath.Dir(b.Observer.PublicKeyFile), "config.json") || digest(jsonBytes(b.Daemon)) != binding.DaemonConfigSHA256 || digest(jsonBytes(b.Observer)) != binding.ObserverConfigSHA256 {
		return ErrFixture
	}
	return nil
}

// VerifyResult is an offline cross-check, not a new witness or qualification
// signer. It requires a host-signed native/root-observer proof and the separate
// durable fixture watermark. Provider success and SaaS integration are separate.
func VerifyResult(r ResultInput, pin string) error {
	b, binding := r.Bundle, r.Profile.Binding
	if r.Version != "runnerd09-lab-result-input-v1" || b.Daemon.Execution == nil {
		return ErrFixture
	}
	if _, err := provision.Parse(jsonBytes(b)); err != nil {
		return err
	}
	if err := ValidatePlanBundle(r.Profile, b); err != nil {
		return err
	}
	x := b.Daemon.Execution
	if katalinux.ValidateLabPlan(r.Profile, []byte(r.LabPublicKey), pin, x.Kata.EvidenceDirectory, b.Daemon.StateDir, standardlinux.Settings{ImageRepository: x.ImageRepository, NetworkID: x.NetworkID, BootstrapRoot: x.BootstrapRoot, RunnerUID: b.Observer.ServiceUID, PidsLimit: x.PidsLimit}) != nil {
		return ErrFixture
	}
	var proof struct {
		Manifest  json.RawMessage `json:"manifest"`
		Signature string          `json:"signature"`
	}
	if json.Unmarshal(r.Proof, &proof) != nil {
		return ErrFixture
	}
	block, _ := pem.Decode([]byte(r.FixtureConfig.HostPublicKey))
	if block == nil {
		return ErrFixture
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return ErrFixture
	}
	public, ok := parsed.(ed25519.PublicKey)
	sig, sigErr := base64.RawURLEncoding.DecodeString(proof.Signature)
	canonical, canonicalErr := protocol.CanonicalizeJSON(proof.Manifest)
	if !ok || sigErr != nil || canonicalErr != nil || !ed25519.Verify(public, canonical, sig) {
		return ErrFixture
	}
	var m struct {
		Version          string                 `json:"version"`
		TenantID         string                 `json:"tenantId"`
		HostID           string                 `json:"hostId"`
		InstallationID   string                 `json:"installationId"`
		SessionEpoch     string                 `json:"sessionEpoch"`
		KeyID            string                 `json:"keyId"`
		EndpointIdentity string                 `json:"endpointIdentity"`
		ExecutionID      string                 `json:"executionId"`
		Generation       string                 `json:"generation"`
		AttemptID        string                 `json:"attemptId"`
		SpecHash         string                 `json:"specHash"`
		ProfileVersion   string                 `json:"profileVersion"`
		ResourceID       string                 `json:"resourceId"`
		State            string                 `json:"state"`
		LastSequence     string                 `json:"lastSequence"`
		AckSequence      string                 `json:"ackSequence"`
		Spec             protocol.ExecutionSpec `json:"spec"`
		Physical         katalinux.Evidence     `json:"physical"`
	}
	if json.Unmarshal(proof.Manifest, &m) != nil {
		return ErrFixture
	}
	profileID, _ := katalinux.ProfileID(r.Profile.Manifest)
	f, config := r.Fixture, r.FixtureConfig
	spec := config.Start.Spec
	configCanonical, _ := protocol.CanonicalizeJSON(jsonBytes(config))
	specCanonical, _ := protocol.CanonicalizeJSON(jsonBytes(spec))
	proofSpec, _ := protocol.CanonicalizeJSON(jsonBytes(m.Spec))
	if config.CaseID != binding.CaseID || config.Identity.HostId != binding.HostID || config.BootID != binding.BootID || config.EndpointIdentity != r.Profile.Manifest.EndpointIdentity || m.Version != "runnerd09-host-evidence-v1" || m.TenantID != binding.TenantID || m.HostID != binding.HostID || m.InstallationID != binding.InstallationID || m.KeyID != config.Identity.KeyId || m.SessionEpoch != config.Identity.SessionEpoch || m.ExecutionID != spec.ExecutionId || m.Generation != spec.Generation || m.AttemptID != spec.AttemptId || m.SpecHash != spec.SpecHash || m.ProfileVersion != profileID || m.EndpointIdentity != config.EndpointIdentity || m.State != "cleaned" || m.LastSequence != m.AckSequence || m.AckSequence == "0" || string(specCanonical) != string(proofSpec) {
		return ErrFixture
	}
	sequence, err := strconv.ParseUint(m.AckSequence, 10, 64)
	if err != nil || sequence < 1 || sequence > 1000 || uint64(len(f.Events)) != sequence || f.Version != "runnerd09-fixture-state-v1" || f.CaseID != binding.CaseID || f.ConfigHash != digest(configCanonical) || f.Sequence != m.AckSequence || !f.Exited || !f.ReservationReleased || f.InventoryResources != 0 || f.Receipts[config.Start.CommandId] != config.Start.PayloadHash || f.Receipts[config.Cleanup.CommandId] != config.Cleanup.PayloadHash {
		return ErrFixture
	}
	for i := uint64(1); i <= sequence; i++ {
		if hash, err := hex.DecodeString(f.Events[strconv.FormatUint(i, 10)]); err != nil || len(hash) != 32 {
			return ErrFixture
		}
	}
	inventory, e1 := strconv.ParseUint(f.InventoryGeneration, 10, 64)
	floor, e2 := strconv.ParseUint(f.CleanupInventoryFloor, 10, 64)
	p := m.Physical
	a, group, disk := p.Absence, p.Cgroup, p.Block
	nameHash := sha256.Sum256([]byte(binding.InstallationID + "\x00" + spec.ExecutionId + "\x00" + spec.Generation + "\x00" + spec.SpecHash))
	name := "nrd-" + hex.EncodeToString(nameHash[:])
	if e1 != nil || e2 != nil || inventory <= floor || p.Version != "runnerd09-physical-v1" || p.Profile != profileID || p.Container != m.ResourceID || len(m.ResourceID) != 64 || p.SpecHash != spec.SpecHash || p.Generation != spec.Generation || p.Prepared || len(p.Processes) != 2 || a == nil || !a.ContainerAbsent || !a.SandboxAbsent || !a.VMAbsent || !a.NetworkRemoved || !a.StorageRemoved || !a.CgroupRemoved || !a.DeviceDetached || !a.MountsRemoved || a.ObservationSource != "qualified-host-procfs-runtime-state-v1" || a.VerifiedAt == "" || group == nil || group.Phase != "released" || group.Profile != profileID || group.Name != name || group.Inode == 0 || group.Device == 0 || disk == nil || disk.Name != name || disk.Profile != profileID || disk.Bytes != r.Profile.Manifest.Storage.Block.Bytes {
		return ErrFixture
	}
	for _, process := range p.Processes {
		if process.PID < 1 || process.Start == "" || (process.Executable != r.Profile.Manifest.QEMUBinary && process.Executable != r.Profile.Manifest.ShimBinary) {
			return ErrFixture
		}
	}
	if disk.Labels[dockerengine.LabelPrefix+"execution"] != spec.ExecutionId || disk.Labels[dockerengine.LabelPrefix+"spec"] != spec.SpecHash || disk.Labels[dockerengine.LabelPrefix+"installation"] != binding.InstallationID {
		return ErrFixture
	}
	unit := "neticora-runnerd-e" + name[4:] + ".slice"
	cpu, _ := strconv.ParseUint(r.Profile.Manifest.Budget.Effective.CpuMillis, 10, 64)
	memory, _ := strconv.ParseUint(r.Profile.Manifest.Budget.Effective.MemoryBytes, 10, 64)
	uuidHash := sha256.Sum256([]byte(profileID + "\x00" + name))
	v := hex.EncodeToString(uuidHash[:16])
	uuid := v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:]
	owner, ownerErr := hex.DecodeString(group.Owner)
	if group.Version != "runnerd09-host-cgroup-v1" || group.Unit != unit || group.Path != "/neticora.slice/neticora-runnerd.slice/"+unit || group.BootID != binding.BootID || group.CPUQuota != cpu*1000 || group.MemoryBytes != memory || group.PidsLimit != r.Profile.Manifest.HostCgroup.PidsLimit || ownerErr != nil || len(owner) != 32 || disk.Version != "runnerd09-block-allocation-v1" || disk.UUID != uuid || disk.FileInode == 0 || disk.FileDevice != r.Profile.Manifest.Storage.Block.Pool.Device || disk.LoopDevice == 0 || disk.BootID != binding.BootID || p.Processes[0].Executable == p.Processes[1].Executable {
		return ErrFixture
	}
	return nil
}
