//go:build linux

package execution

import (
	"context"
	"errors"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

func TestRuntimePressureBlocksAdmissionButKeepsReceiptAndCleanup(t *testing.T) {
	c, runtime, _, execution := setup(t)
	ctx := context.Background()
	runtime.pressure = true
	before := c.Store.Health(ctx).Revision
	if receipt, err := c.accept(ctx, execution.Command); err != nil || !receipt.Duplicate {
		t.Fatal(receipt, err)
	}
	if c.Store.Health(ctx).Revision != before {
		t.Fatal("receipt replay wrote journal")
	}
	next := storetest.Object(t, storetest.Start(t, "new"))
	next["spec"].(map[string]any)["templateVersion"] = standardlinux.TemplateVersion
	if _, err := c.accept(ctx, storetest.Encode(t, "HostCommand", next)); !errors.Is(err, dockerengine.ErrStoragePressure) {
		t.Fatal(err)
	}
	if err := c.execution(ctx, execution); !errors.Is(err, dockerengine.ErrStoragePressure) || runtime.creates != 0 {
		t.Fatal(err)
	}
	runtime.pressure = false
	if err := c.execution(ctx, execution); err != nil {
		t.Fatal(err)
	}
	execution = current(t, c)
	runtime.pressure = true
	command := storetest.Encode(t, "HostCommand", map[string]any{"commandId": "pressure-cleanup", "kind": "cleanup", "executionId": execution.Identity.ExecutionID, "generation": "1"})
	if _, err := c.accept(ctx, command); err != nil {
		t.Fatal("cleanup blocked by disk pressure", err)
	}
	if err := c.execution(ctx, execution); err != nil {
		t.Fatal(err)
	}
	if row := current(t, c); row.State != "cleaned" || row.CleanupPending || runtime.starts != 1 {
		t.Fatal("pressure lost cleanup", row.State)
	}
}

type lostStartRuntime struct {
	*fakeRuntime
	lost bool
}

func (r *lostStartRuntime) Start(ctx context.Context, id string, p dockerengine.Plan, authorize func() error) (dockerengine.Object, error) {
	o, err := r.fakeRuntime.Start(ctx, id, p, authorize)
	if err == nil && !r.lost {
		r.lost = true
		return dockerengine.Object{}, dockerengine.ErrUnavailable
	}
	return o, err
}

func TestLostStartReplyNeverStartsSamePhysicalAttemptAgain(t *testing.T) {
	c, r, _, e := setup(t)
	c.Runtime = &lostStartRuntime{fakeRuntime: r}
	if err := c.execution(context.Background(), e); !errors.Is(err, dockerengine.ErrUnavailable) {
		t.Fatal(err)
	}
	if r.creates != 1 || r.starts != 1 || current(t, c).State != "prepared" {
		t.Fatal("lost reply changed durable boundary")
	}
	if err := c.execution(context.Background(), current(t, c)); err != nil {
		t.Fatal(err)
	}
	if r.creates != 1 || r.starts != 1 || current(t, c).State != "running" {
		t.Fatal("lost reply reran attempt")
	}
}

type incompleteRuntime struct {
	*fakeRuntime
	unknown bool
}

func (r *incompleteRuntime) Inventory(context.Context) ([]string, error) {
	if r.unknown {
		return []string{"unknown-owned-object"}, nil
	}
	return nil, dockerengine.ErrUnavailable
}

func TestPartialOrUnknownInventoryCannotRestoreAdmission(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "partial", true: "unknown-owned"}[unknown], func(t *testing.T) {
			c, r, _, _ := setup(t)
			c.Runtime = &incompleteRuntime{fakeRuntime: r, unknown: unknown}
			if err := c.reconcile(context.Background()); err == nil {
				t.Fatal("invalid inventory accepted")
			}
			if c.Store.Health(context.Background()).Ready || r.starts != 0 || r.removes != 0 {
				t.Fatal("unverified inventory restored admission or mutated resource")
			}
		})
	}
}
