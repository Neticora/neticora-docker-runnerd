//go:build linux

package execution

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

type diskLostStart struct {
	*storageRuntime
	lost bool
}

func (r *diskLostStart) Start(ctx context.Context, id string, plan dockerengine.Plan, authorize func() error) (dockerengine.Object, error) {
	o, e := r.storageRuntime.Start(ctx, id, plan, authorize)
	if e == nil && !r.lost {
		r.lost = true
		return dockerengine.Object{}, dockerengine.ErrUnavailable
	}
	return o, e
}

func TestDiskExecutionRecoversRealJournalReopenWithoutSecondLaunch(t *testing.T) {
	for _, fault := range []string{"lost-start-response", "interrupted-cleanup", "cancellation-before-start"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			os.Chmod(dir, 0700)
			c, r, remote, e := setupTemplateAt(t, standardlinux.DiskTemplateVersion, dir)
			c.Profile.StorageRoot = t.TempDir()
			os.Chmod(c.Profile.StorageRoot, 0700)
			c.RuntimeStoragePaths = []string{c.KeysDirectory}
			runtime := &storageRuntime{fakeRuntime: r}
			c.Runtime = runtime
			if fault == "cancellation-before-start" {
				r.afterEnsure = func() {
					cancel := storetest.Encode(t, "HostCommand", map[string]any{"commandId": "cancel-before-start", "kind": "cancel", "executionId": e.Identity.ExecutionID, "generation": e.Identity.Generation})
					if _, err := c.accept(ctx, cancel); err != nil {
						t.Fatal(err)
					}
				}
			}
			if fault == "lost-start-response" {
				c.Runtime = &diskLostStart{storageRuntime: runtime}
				if err := c.execution(ctx, e); !errors.Is(err, dockerengine.ErrUnavailable) {
					t.Fatal(err)
				}
			} else if err := c.execution(ctx, e); err != nil && fault != "cancellation-before-start" {
				t.Fatal(err)
			}
			if fault == "interrupted-cleanup" {
				e = current(t, c)
				authorizeCleanup(t, c, e)
				runtime.disconnectAfterRemove = true
				if err := c.execution(ctx, e); err == nil {
					t.Fatal("remove reply loss not injected")
				}
				runtime.disconnectAfterRemove = false
			}
			before := current(t, c)
			journalID := c.Store.Health(ctx).JournalID
			if err := c.Store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err := journal.OpenRecovery(ctx, dir, journal.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			// New controller has no in-memory issuance, cancellation or inventory state.
			next := &Controller{Store: store, Runtime: runtime, Remote: remote, Scope: c.Scope, Authority: c.Authority, Profile: c.Profile, Policy: c.Policy, VerifyImage: c.VerifyImage, KeysDirectory: c.KeysDirectory, Organization: c.Organization, Pool: c.Pool, Drained: c.Drained, RuntimeStoragePaths: c.RuntimeStoragePaths}
			if err = next.reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			after := current(t, next)
			if store.Health(ctx).JournalID != journalID || before.Identity != after.Identity || before.CommandID != after.CommandID || string(before.StartRequest) != string(after.StartRequest) {
				t.Fatal("reopen changed durable attempt")
			}
			if fault == "cancellation-before-start" {
				if r.creates != 1 || r.starts != 0 {
					t.Fatal("cancelled disk work launched")
				}
			} else if r.creates != 1 || r.starts != 1 {
				t.Fatal("physical attempt repeated", r.creates, r.starts)
			}
			if fault == "interrupted-cleanup" && after.State != "cleaned" {
				t.Fatal("cleanup did not resume", after.State)
			}
			if after.CleanupPending && after.State == "cleaned" {
				t.Fatal("cleanup obligation discarded")
			}
			if _, err = store.Executions(ctx, agent.ExecutionCursor{}, 100); err != nil {
				t.Fatal(err)
			}
		})
	}
}
