package katalinux

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

func blockFixture() Manifest {
	m := fixture()
	m.Version = BlockVersion
	m.Storage.Runtime.UUID = "12345678-1234-1234-1234-123456789abc"
	m.Storage.Runtime.BackingDevice = "/dev/disk/by-id/runtime-fixture"
	m.GuestStorageDriver = "overlay2"
	m.GuestCapabilities = append(m.GuestCapabilities, "SYS_ADMIN", "DAC_OVERRIDE")
	m.Storage.Graph = Filesystem{}
	m.Storage.Workspace = Filesystem{}
	m.Storage.Block = &BlockStorage{Method: "preallocated-raw-loop-virtio-blk-v1", Filesystem: "ext4", Transport: "virtio-blk-pci", Pool: Filesystem{Root: "/qualified/block", Device: 4, Bytes: 3 << 30, UUID: "87654321-4321-4321-4321-cba987654321", BackingDevice: "/dev/disk/by-id/pool-fixture"}, Bytes: 2 << 30, HeadroomBytes: 256 << 20, DeviceDirectory: "/run/qualified/observer/devices", MkfsBinary: "/qualified/mkfs.ext4", AttachmentReference: "unit fixture only; NOT runtime qualification", PhysicalReservationReference: "unit fixture only; NOT physical qualification"}
	m.Files[m.Storage.Block.MkfsBinary] = strings.Repeat("c", 64)
	m.Files["/etc/mke2fs.conf"] = strings.Repeat("d", 64)
	for i := 1; i <= 10; i++ {
		m.Acceptance[fmt.Sprintf("storage-%02d", i)] = "unit fixture only; NOT a live storage result"
	}
	m.Budget.Effective.StorageBytes = "6442450944"
	m.Budget.Overhead.StorageBytes = "4294967296"
	return m
}
func TestBlockV2PlanOnlyMapsItsOwnedExecutionDisk(t *testing.T) {
	p := profile(blockFixture())
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	s := protocol.ExecutionSpec{ExecutionId: "execution", AttemptId: "attempt", Generation: "1", SpecHash: strings.Repeat("d", 64), IsolationProfile: "isolated", ProfileVersion: p.ID, TemplateVersion: BlockTemplate, ImageDigest: p.Manifest.ImageDigest, Resources: p.Manifest.Budget.Effective}
	plan, err := p.Plan(agent.StoreScope{InstallationID: "installation", TenantID: "tenant", HostID: "host", EndpointIdentity: p.Manifest.EndpointIdentity}, s)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RecoveryOnly || plan.HostConfig.Privileged || len(plan.HostConfig.Devices) != 1 || len(plan.HostConfig.Mounts) != 2 {
		t.Fatal("unsafe block plan")
	}
	d := plan.HostConfig.Devices[0]
	if d.PathOnHost != p.blockNode(plan.Name) || d.PathInContainer != "/dev/neticora-execution" || d.CgroupPermissions != "rw" {
		t.Fatal("unscoped block mapping")
	}
	var guest GuestBlockSettings
	if len(plan.Config.Cmd) != 2 || json.Unmarshal([]byte(plan.Config.Cmd[1]), &guest) != nil || guest.UUID != p.blockUUID(plan.Name) || guest.Bytes != p.Manifest.Storage.Block.Bytes {
		t.Fatal("guest identity not bound to allocation")
	}
	if _, ok := plan.HostConfig.Tmpfs["/tmp"]; ok {
		t.Fatal("scratch bypasses execution block boundary")
	}
	old := s
	s.Generation = "2"
	next, err := p.Plan(agent.StoreScope{InstallationID: "installation"}, s)
	if err != nil || next.Name == plan.Name || p.blockUUID(next.Name) == guest.UUID {
		t.Fatal("generation reuses storage identity")
	}
	s = old
	recovery, err := p.RecoveryPlan(agent.StoreScope{InstallationID: "installation"}, s)
	if err != nil || !recovery.RecoveryOnly {
		t.Fatal("recovery can launch")
	}
	raw, err := json.Marshal(p.Manifest)
	if err != nil || strings.Contains(string(raw), `"graph"`) || strings.Contains(string(raw), `"workspace"`) {
		t.Fatal("legacy shared storage leaked into v2 descriptor")
	}
}
func TestBlockV2RejectsIncompleteOrOvercommittedQualification(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"sparse contract":             func(m *Manifest) { m.Storage.Block.Method = "sparse-file" },
		"host filesystem sharing":     func(m *Manifest) { m.Storage.Block.Transport = "virtio-fs" },
		"missing allocation evidence": func(m *Manifest) { m.Storage.Block.PhysicalReservationReference = "" },
		"missing attachment evidence": func(m *Manifest) { m.Storage.Block.AttachmentReference = "" },
		"no host headroom":            func(m *Manifest) { m.Storage.Block.HeadroomBytes = 0 },
		"oversized disk":              func(m *Manifest) { m.Storage.Block.Bytes = 4 << 30 },
		"unreserved pool":             func(m *Manifest) { m.Storage.Block.Pool.Bytes = 8 << 30 },
		"missing storage gate":        func(m *Manifest) { delete(m.Acceptance, "storage-10") },
		"unsigned formatter":          func(m *Manifest) { delete(m.Files, m.Storage.Block.MkfsBinary) },
		"legacy host graph":           func(m *Manifest) { m.Storage.Graph = Filesystem{Root: "/shared", Device: 5, Bytes: 1 << 30} },
		"multiple guests":             func(m *Manifest) { m.Budget.Effective.Slots = "2" },
	} {
		t.Run(name, func(t *testing.T) {
			m := blockFixture()
			mutate(&m)
			if profile(m).validate() == nil {
				t.Fatal("unsafe block profile accepted")
			}
		})
	}
}

func TestFreshBlockLaunchRequiresPinnedFormatterConfiguration(t *testing.T) {
	m := blockFixture()
	delete(m.Files, "/etc/mke2fs.conf")
	p := profile(m)
	if p.RequireLaunchStorage() == nil {
		t.Fatal("new allocation accepted mutable formatter defaults")
	}
	if err := p.validate(); err != nil {
		t.Fatal("historical descriptor became unreadable", err)
	}
	s := protocol.ExecutionSpec{ExecutionId: "historical", AttemptId: "attempt", Generation: "1", SpecHash: strings.Repeat("e", 64), IsolationProfile: "isolated", ProfileVersion: p.ID, TemplateVersion: BlockTemplate, ImageDigest: m.ImageDigest, Resources: m.Budget.Effective}
	if plan, err := p.RecoveryPlan(agent.StoreScope{InstallationID: "fixture"}, s); err != nil || !plan.RecoveryOnly {
		t.Fatal("historical recovery blocked by new formatting requirement", err)
	}
}
