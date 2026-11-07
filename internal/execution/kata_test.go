package execution

import (
	"errors"
	"strings"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

func TestKataLaunchAndRecoveryPlanningRemainSeparate(t *testing.T) {
	scope := agent.StoreScope{InstallationID: "installation", TenantID: "tenant", HostID: "host", EndpointIdentity: "docker-historical"}
	budget := protocol.ResourceBudget{CpuMillis: "1250", MemoryBytes: "1342177280", StorageBytes: "5368709120", Slots: "1"}
	p := &katalinux.Profile{
		ID:   "historical-kata-profile",
		Base: standardlinux.Settings{ImageRepository: "registry.invalid/runner", NetworkID: "customer-network", BootstrapRoot: "/run/runnerd/bootstrap", RunnerUID: 10001, PidsLimit: 128},
		Manifest: katalinux.Manifest{
			GuestStorageDriver: "vfs", RuntimeSelector: "kata-qemu-runtime-rs",
			ImageRepository: "registry.invalid/runner", ImageDigest: "sha256:" + strings.Repeat("a", 64),
			Budget:  katalinux.Budget{Guest: protocol.ResourceBudget{CpuMillis: "1000", MemoryBytes: "1073741824"}, Effective: budget},
			Storage: katalinux.Storage{Graph: katalinux.Filesystem{Root: "/historical/graph"}, Workspace: katalinux.Filesystem{Root: "/historical/workspace"}},
		},
	}
	c := &Controller{Kata: p}
	s := protocol.ExecutionSpec{ExecutionId: "execution", AttemptId: "attempt", Generation: "1", SpecHash: strings.Repeat("b", 64), IsolationProfile: "isolated", ProfileVersion: p.ID, TemplateVersion: katalinux.Template, ImageDigest: p.Manifest.ImageDigest, Resources: budget}
	if _, err := c.resolvePlan(scope, s); !errors.Is(err, katalinux.ErrBlockStorageRequired) {
		t.Fatal("legacy Kata launch planning accepted", err)
	}
	plan, err := c.resolveRecoveryPlan(scope, s)
	if err != nil || !plan.RecoveryOnly || plan.Config.Labels[dockerengine.LabelPrefix+"endpoint"] != scope.EndpointIdentity {
		t.Fatal("historical planning lost its recovery restriction or identity", err)
	}
	s.IsolationProfile = "standard"
	if _, err := c.resolveRecoveryPlan(scope, s); !errors.Is(err, katalinux.ErrQualification) {
		t.Fatal("historical Kata command downgraded to standard", err)
	}
}
