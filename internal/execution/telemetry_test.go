package execution

import (
	"context"
	"testing"
)

type unownedTelemetryRuntime struct{ *fakeRuntime }

func (r unownedTelemetryRuntime) Inventory(ctx context.Context) ([]string, error) {
	ids, err := r.fakeRuntime.Inventory(ctx)
	return append(ids, "unowned-runtime-object"), err
}

func TestTelemetryOnlyObservesOriginalClaimsAndCannotReconcileUnknownResources(t *testing.T) {
	c, r, _, e := setup(t)
	ctx := context.Background()
	if err := c.execution(ctx, e); err != nil {
		t.Fatal(err)
	}
	before := c.Store.Health(ctx)
	targets, complete := c.telemetryTargets(ctx, r)
	if !complete || len(targets) != 1 || targets[0].ResourceID != r.object.ID {
		t.Fatal("original running resource not measured", targets, complete)
	}
	_, complete = c.telemetryTargets(ctx, unownedTelemetryRuntime{r})
	if complete {
		t.Fatal("unknown resource reported as a complete execution list")
	}
	after := c.Store.Health(ctx)
	if after.Revision != before.Revision || r.creates != 1 || r.starts != 1 || r.stops != 0 || r.removes != 0 {
		t.Fatal("observation changed original lifecycle")
	}
	c.Store.Invalidate(ctx, "test unknown recovery")
	targets, complete = c.telemetryTargets(ctx, r)
	if complete || len(targets) != 0 {
		t.Fatal("unreconciled journal granted resource ownership")
	}
}
