//go:build linux && runnerd_qualification

package qualfixture_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/qualfixture"
)

// Synthetic signed unit fixture; no filesystem/process/VM claim is made here.
func resultFixture(t *testing.T) (qualfixture.ResultInput, string, ed25519.PrivateKey) {
	t.Helper()
	spec, f := prepareInputs(t)
	parent := t.TempDir()
	os.Chmod(parent, 0700)
	output := filepath.Join(parent, "plan")
	receipt, err := qualfixture.Prepare(spec, output)
	if err != nil {
		t.Fatal(err)
	}
	var r qualfixture.ResultInput
	read := func(name string, out any) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(output, name))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
	read("client/profile.json", &r.Profile)
	read("review-bundle-input.json", &r.Bundle)
	read("operator/fixture.json", &r.FixtureConfig)
	public, _ := os.ReadFile(filepath.Join(output, "client/lab-public.pem"))
	r.LabPublicKey = string(public)
	r.Version = "runnerd09-lab-result-input-v1"
	start := r.FixtureConfig.Start
	identity := r.FixtureConfig.Identity
	profile := receipt.ProfileVersion
	hash := sha256.Sum256([]byte(identity.HostId + "\x00" + start.Spec.ExecutionId + "\x00" + start.Spec.Generation + "\x00" + start.Spec.SpecHash))
	name := "nrd-" + hex.EncodeToString(hash[:])
	unit := "neticora-runnerd-e" + name[4:] + ".slice"
	uuidHash := sha256.Sum256([]byte(profile + "\x00" + name))
	v := hex.EncodeToString(uuidHash[:16])
	uuid := v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:]
	cpu, _ := strconv.ParseUint(r.Profile.Manifest.Budget.Effective.CpuMillis, 10, 64)
	memory, _ := strconv.ParseUint(r.Profile.Manifest.Budget.Effective.MemoryBytes, 10, 64)
	container := strings.Repeat("d", 64)
	physical := katalinux.Evidence{Version: "runnerd09-physical-v1", Profile: profile, Container: container, SpecHash: start.Spec.SpecHash, Generation: "1", Processes: []katalinux.Process{{PID: 10, Start: "1", Executable: r.Profile.Manifest.QEMUBinary}, {PID: 11, Start: "2", Executable: r.Profile.Manifest.ShimBinary}}, Absence: &katalinux.PhysicalAbsence{ContainerAbsent: true, SandboxAbsent: true, VMAbsent: true, NetworkRemoved: true, StorageRemoved: true, CgroupRemoved: true, DeviceDetached: true, MountsRemoved: true, VerifiedAt: "unit fixture only", ObservationSource: "qualified-host-procfs-runtime-state-v1"}, Cgroup: &katalinux.CgroupRecord{Version: "runnerd09-host-cgroup-v1", Profile: profile, Name: name, Unit: unit, Path: "/neticora.slice/neticora-runnerd.slice/" + unit, BootID: r.Profile.Binding.BootID, Owner: strings.Repeat("e", 64), Phase: "released", Inode: 1, Device: 2, CPUQuota: cpu * 1000, MemoryBytes: memory, PidsLimit: r.Profile.Manifest.HostCgroup.PidsLimit}, Block: &katalinux.BlockRecord{Version: "runnerd09-block-allocation-v1", Profile: profile, Name: name, UUID: uuid, Bytes: r.Profile.Manifest.Storage.Block.Bytes, FileInode: 3, FileDevice: r.Profile.Manifest.Storage.Block.Pool.Device, LoopDevice: 4, BootID: r.Profile.Binding.BootID, Labels: map[string]string{dockerengine.LabelPrefix + "execution": start.Spec.ExecutionId, dockerengine.LabelPrefix + "spec": start.Spec.SpecHash, dockerengine.LabelPrefix + "installation": identity.HostId}}}
	manifest := map[string]any{"version": "runnerd09-host-evidence-v1", "tenantId": identity.HostId, "hostId": identity.HostId, "installationId": identity.HostId, "sessionEpoch": identity.SessionEpoch, "keyId": identity.KeyId, "endpointIdentity": r.FixtureConfig.EndpointIdentity, "executionId": start.Spec.ExecutionId, "generation": "1", "attemptId": start.Spec.AttemptId, "specHash": start.Spec.SpecHash, "profileVersion": profile, "resourceId": container, "state": "cleaned", "lastSequence": "1", "ackSequence": "1", "spec": start.Spec, "physical": physical}
	raw, _ := json.Marshal(manifest)
	canonical, _ := protocol.CanonicalizeJSON(raw)
	r.Proof, _ = json.Marshal(map[string]any{"manifest": manifest, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.key, canonical))})
	configRaw, _ := json.Marshal(r.FixtureConfig)
	configCanonical, _ := protocol.CanonicalizeJSON(configRaw)
	configHash := sha256.Sum256(configCanonical)
	r.Fixture = qualfixture.State{Version: "runnerd09-fixture-state-v1", CaseID: r.Profile.Binding.CaseID, ConfigHash: hex.EncodeToString(configHash[:]), InventoryGeneration: "2", CleanupInventoryFloor: "1", Sequence: "1", Exited: true, ReservationReleased: true, Receipts: map[string]string{start.CommandId: start.PayloadHash, r.FixtureConfig.Cleanup.CommandId: r.FixtureConfig.Cleanup.PayloadHash}, Events: map[string]string{"1": strings.Repeat("a", 64)}}
	return r, receipt.AuthorityPin, f.key
}

func TestResultVerifierRejectsMissingAckReleaseScopeAndPhysicalProof(t *testing.T) {
	r, pin, key := resultFixture(t)
	if err := qualfixture.VerifyResult(r, pin); err != nil {
		t.Fatal("complete signed unit fixture rejected", err)
	}
	for _, name := range []string{"watermark", "release", "inventory", "command", "config", "host-signature", "vm-alive", "wrong-cgroup", "missing-loop", "prepared-only", "wrong-spec"} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(r)
			var bad qualfixture.ResultInput
			json.Unmarshal(raw, &bad)
			switch name {
			case "watermark":
				bad.Fixture.Sequence = "0"
			case "release":
				bad.Fixture.ReservationReleased = false
			case "inventory":
				bad.Fixture.InventoryGeneration = bad.Fixture.CleanupInventoryFloor
			case "command":
				delete(bad.Fixture.Receipts, bad.FixtureConfig.Cleanup.CommandId)
			case "config":
				bad.Bundle.Daemon.ControlPlaneURL = "https://127.0.0.2:16443/api/v1/runner-hosts"
			default:
				var proof map[string]any
				json.Unmarshal(bad.Proof, &proof)
				manifest := proof["manifest"].(map[string]any)
				physical := manifest["physical"].(map[string]any)
				switch name {
				case "host-signature":
					manifest["state"] = "running"
				case "vm-alive":
					physical["absence"].(map[string]any)["vmAbsent"] = false
				case "wrong-cgroup":
					physical["cgroup"].(map[string]any)["memoryBytes"] = float64(1)
				case "missing-loop":
					physical["block"].(map[string]any)["loopDevice"] = float64(0)
				case "prepared-only":
					physical["prepared"] = true
				case "wrong-spec":
					manifest["specHash"] = strings.Repeat("0", 64)
				}
				if name != "host-signature" {
					m, _ := json.Marshal(manifest)
					canonical, _ := protocol.CanonicalizeJSON(m)
					proof["signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, canonical))
				}
				bad.Proof, _ = json.Marshal(proof)
			}
			if qualfixture.VerifyResult(bad, pin) == nil {
				t.Fatal("incomplete proof accepted")
			}
		})
	}
}
