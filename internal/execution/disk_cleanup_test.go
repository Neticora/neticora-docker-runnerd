//go:build linux

package execution

import (
	"context"
	"errors"
	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/executionstorage"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	"os"
	"path/filepath"
	"testing"
)

type storageRuntime struct {
	*fakeRuntime
	retirementErr error
}

func (r *storageRuntime) VerifyStorageReleased(context.Context, string, dockerengine.Plan) error {
	return r.retirementErr
}
func diskFixture(t *testing.T) (*Controller, *storageRuntime, agent.Execution) {
	t.Helper()
	c, f, _, e := setupTemplate(t, standardlinux.DiskTemplateVersion)
	c.Profile.StorageRoot = t.TempDir()
	os.Chmod(c.Profile.StorageRoot, 0700)
	c.RuntimeStoragePaths = []string{c.KeysDirectory}
	r := &storageRuntime{fakeRuntime: f}
	c.Runtime = r
	return c, r, e
}
func authorizeCleanup(t *testing.T, c *Controller, e agent.Execution) {
	t.Helper()
	raw := storetest.Encode(t, "HostCommand", map[string]any{"commandId": "cleanup-a", "kind": "cleanup", "executionId": e.Identity.ExecutionID, "generation": e.Identity.Generation})
	if _, err := c.Store.AcceptCommand(context.Background(), c.Scope, raw); err != nil {
		t.Fatal(err)
	}
}
func TestDiskCleanupPrecedesCleanedEventAndReservationRelease(t *testing.T) {
	for _, failure := range []string{"none", "retirement", "unknown-child", "lost-remove"} {
		t.Run(failure, func(t *testing.T) {
			c, r, e := diskFixture(t)
			ctx := context.Background()
			if err := c.execution(ctx, e); err != nil {
				t.Fatal(err)
			}
			e = current(t, c)
			record, err := c.storage().Record(ctx, e.Identity)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(record.Root, record.Name)
			os.WriteFile(filepath.Join(path, "workspace", "artifact"), []byte("delivered"), 0600)
			authorizeCleanup(t, c, e)
			switch failure {
			case "retirement":
				r.retirementErr = executionstorage.ErrQuarantined
			case "unknown-child":
				os.WriteFile(filepath.Join(path, "unknown"), []byte("unknown"), 0600)
			case "lost-remove":
				r.disconnectAfterRemove = true
			}
			err = c.execution(ctx, e)
			latest := current(t, c)
			if failure != "none" {
				if err == nil || latest.State == "cleaned" || !latest.CleanupPending {
					t.Fatal("unverified disposal finalized", latest, err)
				}
				if _, err = os.Stat(path); err != nil {
					t.Fatal("uncertain storage lost", err)
				}
				return
			}
			if err != nil || latest.State != "cleaned" {
				t.Fatal(latest, err)
			}
			if _, err = os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("cleaned before physical disposal", err)
			}
			record, err = c.storage().Record(ctx, e.Identity)
			if err != nil || record.State != "disposed" {
				t.Fatal(record, err)
			}
		})
	}
}
func TestDiskCleanupRequiresRuntimeRetirementVerifier(t *testing.T) {
	c, r, e := diskFixture(t)
	ctx := context.Background()
	if err := c.execution(ctx, e); err != nil {
		t.Fatal(err)
	}
	e = current(t, c)
	authorizeCleanup(t, c, e)
	c.Runtime = r.fakeRuntime
	if err := c.execution(ctx, e); !errors.Is(err, executionstorage.ErrQuarantined) {
		t.Fatal("missing proof accepted", err)
	}
}

func TestNewLegacyWorkspaceAdmissionRejectedButOriginalReceiptRetained(t *testing.T) {
	c, _, _, e := setup(t)
	ctx := context.Background()
	if r, err := c.accept(ctx, e.Command); err != nil || !r.Duplicate {
		t.Fatal("original receipt lost", err)
	}
	v := storetest.Object(t, storetest.Start(t, "legacy-new"))
	v["spec"].(map[string]any)["templateVersion"] = standardlinux.TemplateVersion
	if _, err := c.accept(ctx, storetest.Encode(t, "HostCommand", v)); !errors.Is(err, standardlinux.ErrAdmission) {
		t.Fatal("new tmpfs execution admitted", err)
	}
}
