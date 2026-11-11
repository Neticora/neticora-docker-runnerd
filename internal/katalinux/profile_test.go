package katalinux

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

// Structural fixture only: these references intentionally claim no live result.
func fixture() Manifest {
	m := Manifest{Version: Version, Qualified: true, GuestStorageDriver: "vfs", RuntimeImplementation: "runtime-rs", Hypervisor: "qemu", EndpointIdentity: "docker-fixture", ConfigurationGeneration: "1", VerifiedAt: "2026-01-01T00:00:00Z", ExpiresAt: "2026-01-01T01:00:00Z", HostKernel: "fixture", DockerVersion: "fixture", RuntimeSelector: "kata-qemu-runtime-rs", KataVersion: "fixture", QEMUVersion: "fixture", GuestKernelVersion: "fixture", GuestImageVersion: "fixture", ImageRepository: "registry.invalid/fixture", ImageDigest: "sha256:" + strings.Repeat("a", 64), QEMUBinary: "/qualified/qemu", ShimBinary: "/qualified/shim", DockerConfig: "/qualified/docker.json", ObserverConfig: "/qualified/observer.json", RuntimeConfig: "/qualified/kata.toml", HostOSFile: "/qualified/os-release", GuestKernel: "/qualified/kernel", GuestImage: "/qualified/rootfs", VMNamePrefix: "sandbox-", SandboxRoots: []string{"/qualified/runtime/sbs"}, GuestCapabilities: []string{"SETUID", "SETGID", "CHOWN"}, SecurityReview: "unit fixture only; not a qualification", Files: map[string]string{}, Acceptance: map[string]string{}, Deadlines: Deadlines{90, 30, 30, 3600}}
	for _, path := range []string{m.QEMUBinary, m.ShimBinary, m.DockerConfig, m.ObserverConfig, m.RuntimeConfig, m.HostOSFile, m.GuestKernel, m.GuestImage} {
		m.Files[path] = strings.Repeat("b", 64)
	}
	for _, g := range []struct {
		p string
		n int
	}{{"original-", 14}, {"review-", 24}} {
		for i := 1; i <= g.n; i++ {
			m.Acceptance[fmt.Sprintf("%s%02d", g.p, i)] = "unit fixture only; NOT a live qualification"
		}
	}
	m.Budget = Budget{Guest: protocol.ResourceBudget{CpuMillis: "1000", MemoryBytes: "1073741824", StorageBytes: "2147483648", Slots: "1"}, Overhead: protocol.ResourceBudget{CpuMillis: "250", MemoryBytes: "268435456", StorageBytes: "3221225472", Slots: "0"}, Effective: protocol.ResourceBudget{CpuMillis: "1250", MemoryBytes: "1342177280", StorageBytes: "5368709120", Slots: "1"}}
	m.Storage = Storage{Graph: Filesystem{Root: "/qualified/graph", Device: 1, Bytes: 1 << 30}, Workspace: Filesystem{Root: "/qualified/work", Device: 2, Bytes: 1 << 30}, Runtime: Filesystem{Root: "/qualified/runtime", Device: 3, Bytes: 1 << 30}, DockerRoot: "/qualified/docker", OuterBytes: 1 << 30, LogBytes: 20 << 20, ManagementFreeBytes: 256 << 20}
	return m
}
func profile(m Manifest) *Profile {
	id, _ := ProfileID(m)
	return &Profile{Manifest: m, ID: id, EvidenceDirectory: "/qualified/evidence", JournalDirectory: "/qualified/journal", Base: standardlinux.Settings{ImageRepository: m.ImageRepository, NetworkID: strings.Repeat("c", 64), BootstrapRoot: "/run/fixture", RunnerUID: 10001, PidsLimit: 128}}
}
func TestQualificationRejectsMissingEvidenceFallbackAndUnreservedOverhead(t *testing.T) {
	if profile(fixture()).validate() != nil {
		t.Fatal("structural fixture rejected")
	}
	for name, change := range map[string]func(*Manifest){"unqualified": func(m *Manifest) { m.Qualified = false }, "runtime fallback": func(m *Manifest) { m.RuntimeSelector = "runc" }, "Go runtime": func(m *Manifest) { m.RuntimeImplementation = "go" }, "storage fallback": func(m *Manifest) { m.GuestStorageDriver = "overlay2" }, "missing acceptance": func(m *Manifest) { delete(m.Acceptance, "review-24") }, "missing observer pin": func(m *Manifest) { delete(m.Files, m.ObserverConfig) }, "missing overhead": func(m *Manifest) { m.Budget.Overhead.MemoryBytes = "0" }, "wrong effective": func(m *Manifest) { m.Budget.Effective.MemoryBytes = "1073741824" }, "fractional guest": func(m *Manifest) { m.Budget.Guest.CpuMillis = "500"; m.Budget.Effective.CpuMillis = "750" }, "concurrent guests": func(m *Manifest) { m.Budget.Effective.Slots = "2" }} {
		t.Run(name, func(t *testing.T) {
			m := fixture()
			change(&m)
			if profile(m).validate() == nil {
				t.Fatal("unsafe profile accepted")
			}
		})
	}
}
func TestImmutableProfileAndHistoricalPlan(t *testing.T) {
	p := profile(fixture())
	s := protocol.ExecutionSpec{ExecutionId: "execution", AttemptId: "attempt", Generation: "1", SpecHash: strings.Repeat("d", 64), IsolationProfile: "isolated", ProfileVersion: p.ID, TemplateVersion: Template, ImageDigest: p.Manifest.ImageDigest, Resources: p.Manifest.Budget.Effective}
	scope := agent.StoreScope{InstallationID: "installation", TenantID: "tenant", HostID: "host", EndpointIdentity: p.Manifest.EndpointIdentity}
	if _, err := p.Plan(scope, s); !errors.Is(err, ErrBlockStorageRequired) {
		t.Fatal("legacy profile produced a launch plan", err)
	}
	plan, e := p.RecoveryPlan(scope, s)
	if e != nil {
		t.Fatal(e)
	}
	if !plan.RecoveryOnly || plan.HostConfig.Privileged || len(plan.HostConfig.Devices) != 0 || plan.HostConfig.Runtime == "runc" || plan.Config.User != "0:0" || len(plan.HostConfig.Mounts) != 4 || len(plan.HostConfig.StorageOpt) != 1 || plan.HostConfig.Annotations["io.katacontainers.config.hypervisor.default_vcpus"] != "1" {
		t.Fatal("unsafe isolated plan")
	}
	engine := &dockerengine.Engine{}
	if err := engine.PrepareImage(context.Background(), plan); !errors.Is(err, dockerengine.ErrRecoveryPlan) {
		t.Fatal("historical plan permitted image preparation", err)
	}
	if _, err := engine.Ensure(context.Background(), plan, nil); !errors.Is(err, dockerengine.ErrRecoveryPlan) {
		t.Fatal("historical plan permitted container creation", err)
	}
	if _, err := engine.Start(context.Background(), "historical", plan, nil); !errors.Is(err, dockerengine.ErrRecoveryPlan) {
		t.Fatal("historical plan permitted container start", err)
	}
	m := fixture()
	m.Storage.Graph.Bytes++
	other, _ := ProfileID(m)
	if other == p.ID {
		t.Fatal("physical tuple mutation did not change profile identity")
	}
	s.IsolationProfile = "standard"
	if _, e = p.RecoveryPlan(agent.StoreScope{}, s); e == nil {
		t.Fatal("isolated profile downgraded")
	}
}
func TestNoLiveQualificationFromStructuralFixture(t *testing.T) {
	p := profile(fixture())
	if p.Check(time.Now()) == nil {
		t.Fatal("fixture masqueraded as host qualification")
	}
	b, e := json.Marshal(p.Manifest)
	if e != nil || !strings.Contains(string(b), "NOT a live qualification") {
		t.Fatal("test references changed")
	}
}

func TestDisposableStorageCannotContainTrustOrJournal(t *testing.T) {
	p := profile(fixture())
	for _, path := range []string{p.Manifest.Storage.Graph.Root + "/credentials.json", p.Manifest.Storage.Workspace.Root + "/policy.json", p.Manifest.Storage.Runtime.Root + "/journal", p.Manifest.Storage.DockerRoot} {
		if p.ProtectPaths(path) == nil {
			t.Fatalf("private path accepted on disposable storage: %s", path)
		}
	}
	m := fixture()
	m.SandboxRoots = []string{"/unbounded/sandboxes"}
	if profile(m).validate() == nil {
		t.Fatal("sandbox outside bounded runtime filesystem accepted")
	}
	m = fixture()
	m.Storage.Workspace.Root = m.Storage.Graph.Root + "/workspace"
	if profile(m).validate() == nil {
		t.Fatal("overlapping disposable filesystems accepted")
	}
}
