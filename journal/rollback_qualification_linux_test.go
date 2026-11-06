//go:build linux && runnerd_qualification

package journal

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
)

// External coordination runs compatible shipping services between prepare,
// verify and finish. Only synthetic state in a private lab directory is used.
func TestRunnerd08CompatibleRollbackState(t *testing.T) {
	phase := os.Getenv("RUNNERD08_ROLLBACK_PHASE")
	if phase == "" {
		t.Skip("external compatible shipping-package coordinator required")
	}
	dir := labDirectory(t)
	ctx := context.Background()
	s, err := OpenRecovery(ctx, dir, testOptions(Options{}))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	path := filepath.Join(dir, "public-test-command.json")
	var command []byte
	if phase == "prepare" {
		storetest.Reconcile(t, s, storetest.Scope, "1")
		command = storetest.Start(t, "compatible-rollback")
		if _, err = s.AcceptCommand(ctx, storetest.Scope, command); err != nil {
			t.Fatal(err)
		}
		if err = s.PutStartIntent(ctx, storetest.Scope, storetest.Intent(t, command)); err != nil {
			t.Fatal(err)
		}
		if err = s.RecordObservation(ctx, storetest.Scope, storetest.Event(t, command, 1, "running")); err != nil {
			t.Fatal(err)
		}
		if err = s.RequireCleanup(ctx, storetest.Scope, storetest.Event(t, command, 2, "cleanup-pending")); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, command, 0600); err != nil {
			t.Fatal(err)
		}
	} else {
		command, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	if phase != "prepare" && phase != "verify" && phase != "finish" {
		t.Fatal("unknown phase")
	}
	rows, err := s.Incomplete(ctx, agent.ExecutionCursor{}, 10)
	if err != nil || len(rows) != 1 || !rows[0].CleanupPending || rows[0].LastSequence != "2" || rows[0].AckSequence != "0" {
		t.Fatal("active cleanup facts changed", rows, err)
	}
	if count(t, s, "commands") != 1 || count(t, s, "start_intents") != 1 || count(t, s, "outbox_events") != 2 {
		t.Fatal("duplicate attempt or lost durable facts")
	}
	var released, complete int
	if err = s.db.QueryRowContext(ctx, "SELECT released FROM reservations").Scan(&released); err != nil || released != 0 {
		t.Fatal("reservation lost", err)
	}
	if err = s.db.QueryRowContext(ctx, "SELECT complete FROM cleanup_tasks").Scan(&complete); err != nil || complete != 0 {
		t.Fatal("cleanup falsely completed", err)
	}
	// Every service reopen correctly invalidates runtime knowledge. The fixture
	// supplies a fresh synthetic reconciliation before exercising receipt replay.
	var inventory string
	if err = s.db.QueryRowContext(ctx, "SELECT inventory_generation FROM metadata").Scan(&inventory); err != nil {
		t.Fatal(err)
	}
	parsed, err := strconv.ParseUint(inventory, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	inventory = strconv.FormatUint(parsed+1, 10)
	storetest.Reconcile(t, s, storetest.Scope, inventory, agent.Watermark{ExecutionID: rows[0].Identity.ExecutionID, Generation: rows[0].Identity.Generation, ContiguousSequence: "0"})
	if _, err = s.Receipt(ctx, storetest.Scope, command); err != nil {
		t.Fatal("receipt unavailable after rollback", err)
	}
	if phase == "finish" {
		event := storetest.Event(t, command, 3, "cleaned")
		if err = s.CompleteCleanup(ctx, storetest.Scope, event, storetest.Proof(t, event, inventory)); err != nil {
			t.Fatal(err)
		}
		if count(t, s, "outbox_events") != 3 {
			t.Fatal("cleanup event missing")
		}
		if err = s.db.QueryRowContext(ctx, "SELECT released FROM reservations").Scan(&released); err != nil || released != 1 {
			t.Fatal("verified cleanup did not release reservation", err)
		}
		if err = s.db.QueryRowContext(ctx, "SELECT complete FROM cleanup_tasks").Scan(&complete); err != nil || complete != 1 {
			t.Fatal("verified cleanup task incomplete", err)
		}
	}
	t.Logf("phase=%s schema=3 one_attempt=true original_receipt=true required_facts_preserved=true", phase)
}
