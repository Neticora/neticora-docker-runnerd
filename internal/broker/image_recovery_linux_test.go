//go:build linux

package broker

import (
	"context"
	"errors"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

type observedImageRuntime struct {
	*componentRuntime
	ready        bool
	observations int
}

func (r *observedImageRuntime) ObservePreparedImage(context.Context, dockerengine.Plan) error {
	r.observations++
	if !r.ready {
		return dockerengine.ErrAbsent
	}
	return nil
}
func TestCommittedImageRecoveryObservesWithoutRepeatingEffect(t *testing.T) {
	for _, mode := range []string{"present", "absent", "missing-challenge", "lost-receipt"} {
		t.Run(mode, func(t *testing.T) {
			e, r, base, key, _ := physicalFixture(t)
			observer := &observedImageRuntime{componentRuntime: r, ready: mode != "absent"}
			e.runtime = observer
			e.checkpoint = func(point string, _ ExecutionGrantRequest) error {
				if point == "before-effect" {
					return errors.New("original effect interrupted")
				}
				return nil
			}
			q, s, c := physicalAuthorization(t, e, base, key, "PrepareImage", 0, "")
			if _, err := e.Execute(t.Context(), q, s, c); err == nil {
				t.Fatal("missing interruption")
			}
			if mode == "missing-challenge" {
				if err := e.ledger.root.Remove("challenges/" + q.OperationID + ".json"); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "lost-receipt" {
				if err := e.ledger.root.Remove(q.OperationID + ".json"); err != nil {
					t.Fatal(err)
				}
			}
			lookup := Lookup{ExecutionID: q.ExecutionID, Generation: q.Generation, SpecHash: base.Grant.Binding.SpecHash}
			state, err := e.State(t.Context(), lookup, true)
			if mode == "present" {
				if !errors.Is(err, dockerengine.ErrAbsent) || state.Revision != "1" || state.Phase != "ALLOCATED" || state.Operations["PrepareImage"].OperationID != q.OperationID {
					t.Fatal("original image did not reconcile", state, err)
				}
			} else if err == nil || errors.Is(err, dockerengine.ErrAbsent) {
				t.Fatal("unproven image gained progress", mode, err)
			}
			if r.pulls != 0 || r.creates != 0 || r.starts != 0 {
				t.Fatal("reconciliation repeated an effect")
			}
		})
	}
}
