//go:build linux

package journal

import (
	"context"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
)

func TestRetiredACKIsDurableAcrossRestartAndPendingFinalACKCannotBeOmitted(t *testing.T) {
	for _, acknowledged := range []bool{false, true} {
		t.Run(map[bool]string{false: "lost-final-ack", true: "retired"}[acknowledged], func(t *testing.T) {
			ctx, dir := context.Background(), privateDir(t)
			s := recovery(t, dir, Options{})
			storetest.Reconcile(t, s, storetest.Scope, "1")
			start := storetest.Start(t, "retire")
			if _, err := s.AcceptCommand(ctx, storetest.Scope, start); err != nil {
				t.Fatal(err)
			}
			if err := s.RecordObservation(ctx, storetest.Scope, storetest.Event(t, start, 1, "exited")); err != nil {
				t.Fatal(err)
			}
			if err := s.RequireCleanup(ctx, storetest.Scope, storetest.Event(t, start, 2, "cleanup-pending")); err != nil {
				t.Fatal(err)
			}
			cleaned := storetest.Event(t, start, 3, "cleaned")
			if err := s.CompleteCleanup(ctx, storetest.Scope, cleaned, storetest.Proof(t, cleaned, "1")); err != nil {
				t.Fatal(err)
			}
			watermark := agent.Watermark{ExecutionID: "exec-retire", Generation: "1", ContiguousSequence: "3"}
			if acknowledged {
				if err := s.AckEvents(ctx, storetest.Scope, watermark); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s = recovery(t, dir, Options{})
			h := s.Health(ctx)
			checkpoint := agent.RecoveryCheckpoint{JournalID: h.JournalID, Revision: h.Revision, Scope: storetest.Scope, InventoryGeneration: "2", ObservedAt: storetest.Proof(t, storetest.Event(t, start, 3, "cleaned"), "2").ObservedAt}
			err := s.Reconcile(ctx, checkpoint)
			if !acknowledged {
				if err == nil {
					t.Fatal("unacknowledged terminal obligation omitted")
				}
				checkpoint.ServerWatermarks = []agent.Watermark{watermark}
				if err = s.Reconcile(ctx, checkpoint); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal("durably ACKed history required lifetime replay", err)
			}
			if receipt, err := s.Receipt(ctx, storetest.Scope, start); err != nil || !receipt.Duplicate {
				t.Fatal(receipt, err)
			}
			rows, err := s.Executions(ctx, agent.ExecutionCursor{}, 100)
			if err != nil || len(rows) != 1 || rows[0].AckSequence != "3" {
				t.Fatal("retired ACK lost", rows, err)
			}
			checkpoint.InventoryGeneration = "3"
			checkpoint.Revision = s.Health(ctx).Revision
			checkpoint.ServerWatermarks = []agent.Watermark{{ExecutionID: "exec-retire", Generation: "1", ContiguousSequence: "2"}}
			if err = s.Reconcile(ctx, checkpoint); err == nil {
				t.Fatal("retired ACK regressed")
			}
		})
	}
}
