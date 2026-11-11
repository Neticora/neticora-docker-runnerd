//go:build linux

package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
)

func TestFinalAckHousekeepingSurvivesProfileChangeWithoutRuntimeAuthority(t *testing.T) {
	c, _, _, first := setup(t)
	ctx := context.Background()
	cleanHistory(t, c, first.Command, "1", true)
	rows, err := c.Store.Executions(ctx, agent.ExecutionCursor{}, 100)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	e := rows[0]
	original, err := c.plan(e)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(c.Profile.BootstrapRoot, original.Name)
	os.Mkdir(dir, 0700)
	os.WriteFile(filepath.Join(dir, "bootstrap.json"), []byte("private-remnant"), 0600)
	c.Kata = &katalinux.Profile{ID: "different-approved-profile", Base: c.Profile}
	if _, err = c.plan(e); err == nil {
		t.Fatal("new runtime accepted historical runtime contract")
	}
	private, err := c.retiredPrivatePlan(e)
	if err != nil || private.Name != original.Name || !private.RecoveryOnly || private.Config != nil || private.HostConfig != nil {
		t.Fatal("housekeeping gained runnable authority", err)
	}
	if err = c.retiredSecrets(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, "bootstrap.json")); !os.IsNotExist(err) {
		t.Fatal("retired private remnant retained")
	}
	e.AckSequence = "0"
	if _, err = c.retiredPrivatePlan(e); err == nil {
		t.Fatal("unacknowledged history bypassed recovery profile")
	}
	e = rows[0]
	e.Identity.AttemptID = "another-attempt"
	if _, err = c.retiredPrivatePlan(e); err == nil {
		t.Fatal("inconsistent identity authorized private cleanup")
	}
}

func cleanHistory(t *testing.T, c *Controller, start json.RawMessage, inventory string, acknowledged bool) {
	t.Helper()
	ctx := context.Background()
	for sequence, state := range []string{"exited", "cleanup-pending", "cleaned"} {
		event := storetest.Event(t, start, uint64(sequence+1), state)
		var err error
		switch state {
		case "exited":
			err = c.Store.RecordObservation(ctx, c.Scope, event)
		case "cleanup-pending":
			err = c.Store.RequireCleanup(ctx, c.Scope, event)
		case "cleaned":
			err = c.Store.CompleteCleanup(ctx, c.Scope, event, storetest.Proof(t, event, inventory))
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if acknowledged {
		var command protocol.StartCommand
		_ = json.Unmarshal(start, &command)
		if err := c.Store.AckEvents(ctx, c.Scope, agent.Watermark{ExecutionID: command.Spec.ExecutionId, Generation: command.Generation, ContiguousSequence: "3"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRecoveryHasNoLifetimeHistoryLimit(t *testing.T) {
	c, _, remote, first := setup(t)
	ctx := context.Background()
	cleanHistory(t, c, first.Command, "1", true)
	generation := 1
	for i := 0; i < 1001; i++ {
		start := storetest.Start(t, fmt.Sprintf("retired-%04d", i))
		if _, err := c.Store.AcceptCommand(ctx, c.Scope, start); err != nil {
			t.Fatal(err)
		}
		cleanHistory(t, c, start, fmt.Sprint(generation), true)
		if i%50 == 0 {
			generation++
			storetest.Reconcile(t, c.Store, c.Scope, fmt.Sprint(generation))
		}
	}
	// Still recover the original immutable receipt; retirement deletes nothing.
	if receipt, err := c.Store.Receipt(ctx, c.Scope, first.Command); err != nil || !receipt.Duplicate {
		t.Fatal(receipt, err)
	}
	start := storetest.Start(t, "after-history")
	if _, err := c.Store.AcceptCommand(ctx, c.Scope, start); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(start, &remote.start)
	remote.inventory = fmt.Sprint(generation)
	rows, err := c.refresh(ctx)
	if err != nil || len(rows) != 1 || rows[0].Identity.ExecutionID != "exec-after-history" {
		t.Fatal("retired history blocked active recovery", len(rows), err)
	}
	for _, request := range remote.lookups {
		if len(request) != 1 || request[0].ExecutionID != "exec-after-history" {
			t.Fatal("history leaked into bounded lookup", request)
		}
	}
}

func TestRetiredSecretHousekeepingPreservesActiveAndUnexpectedFiles(t *testing.T) {
	for _, unexpected := range []bool{false, true} {
		t.Run(fmt.Sprint(unexpected), func(t *testing.T) {
			c, _, _, retired := setup(t)
			ctx := context.Background()
			cleanHistory(t, c, retired.Command, "1", true)
			start := storetest.Start(t, "still-active")
			if _, err := c.Store.AcceptCommand(ctx, c.Scope, start); err != nil {
				t.Fatal(err)
			}
			active, err := c.Store.Incomplete(ctx, agent.ExecutionCursor{}, 100)
			if err != nil || len(active) != 1 {
				t.Fatal(active, err)
			}
			var retiredDir, activeDir string
			for i, e := range []agent.Execution{retired, active[0]} {
				plan, err := c.plan(e)
				if err != nil {
					t.Fatal(err)
				}
				dir := filepath.Join(c.Profile.BootstrapRoot, plan.Name)
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "bootstrap.json"), []byte("CANARY-BOOTSTRAP"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(c.KeysDirectory, requestID(e)+".key"), []byte("CANARY-RECIPIENT"), 0600); err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					retiredDir = dir
				} else {
					activeDir = dir
				}
			}
			if unexpected {
				if err := os.WriteFile(filepath.Join(retiredDir, "preserve"), []byte("unrecognized"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.retiredSecrets(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(retiredDir, "bootstrap.json")); !os.IsNotExist(err) {
				t.Fatal("retired secret retained", err)
			}
			if _, err := os.Lstat(filepath.Join(c.KeysDirectory, requestID(retired)+".key")); !os.IsNotExist(err) {
				t.Fatal("retired recipient retained", err)
			}
			if raw, err := os.ReadFile(filepath.Join(activeDir, "bootstrap.json")); err != nil || string(raw) != "CANARY-BOOTSTRAP" {
				t.Fatal("active handoff removed", err)
			}
			if _, err := os.Stat(filepath.Join(c.KeysDirectory, requestID(active[0])+".key")); err != nil {
				t.Fatal("active recipient removed", err)
			}
			if unexpected {
				if raw, err := os.ReadFile(filepath.Join(retiredDir, "preserve")); err != nil || string(raw) != "unrecognized" {
					t.Fatal("unknown file removed", err)
				}
			} else if _, err := os.Lstat(retiredDir); !os.IsNotExist(err) {
				t.Fatal("empty retired directory retained", err)
			}
		})
	}
}

func TestSecretPlanRejectsInconsistentStoredIdentity(t *testing.T) {
	c, _, _, original := setup(t)
	for _, change := range []func(*agent.Execution){
		func(e *agent.Execution) { e.CommandID = "another-command" },
		func(e *agent.Execution) { e.Identity.ExecutionID = "another-execution" },
		func(e *agent.Execution) { e.Identity.Generation = "2" },
		func(e *agent.Execution) { e.Identity.SpecHash = strings.Repeat("b", 64) },
		func(e *agent.Execution) { e.Identity.HostID = "another-host" },
	} {
		e := original
		change(&e)
		if _, err := c.plan(e); err == nil {
			t.Fatal("inconsistent identity selected private handoff paths")
		}
	}
}

func TestRecoveryKeepsCancellationSeparateAcrossGenerations(t *testing.T) {
	c, r, remote, e := setup(t)
	remote.recoveryEntries = []protocol.RecoveryEntry{
		{ExecutionId: e.Identity.ExecutionID, Generation: "1", CommandId: e.CommandID, SpecHash: e.Identity.SpecHash, ContiguousSequence: "0", Cancelled: true},
		{ExecutionId: e.Identity.ExecutionID, Generation: "2", CommandId: "new-command", SpecHash: e.Identity.SpecHash, ContiguousSequence: "0", Cancelled: false},
	}
	if _, err := c.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.cancelled[executionKey(e)] || c.cancelled[agent.ExecutionCursor{ExecutionID: e.Identity.ExecutionID, Generation: "2"}] {
		t.Fatal("generation cancellation conflated")
	}
	if err := c.execution(context.Background(), e); err == nil || r.starts != 0 || r.creates != 0 {
		t.Fatal("cancelled generation launched", err)
	}
	remote.recoveryEntries = append(remote.recoveryEntries, remote.recoveryEntries[0])
	if _, err := c.refresh(context.Background()); err == nil {
		t.Fatal("duplicate recovery identity accepted")
	}
}

func TestAcceptedCancellationBeforeStartPreventsLaunch(t *testing.T) {
	c, r, _, e := setup(t)
	r.afterEnsure = func() {
		cancel := storetest.Encode(t, "HostCommand", map[string]any{"commandId": "cancel-before-start", "kind": "cancel", "executionId": e.Identity.ExecutionID, "generation": "1"})
		if _, err := c.accept(context.Background(), cancel); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.execution(context.Background(), e); err == nil || r.starts != 0 {
		t.Fatal("durable pre-start cancellation crossed boundary", err)
	}
}

func TestCancellationBetweenFinalCheckAndDockerStartIsSerialized(t *testing.T) {
	c, r, _, e := setup(t)
	checked, proceed := make(chan struct{}), make(chan struct{})
	r.beforeStart = func() { close(checked); <-proceed }
	done := make(chan error, 1)
	go func() { done <- c.execution(context.Background(), e) }()
	select {
	case <-checked:
	case <-time.After(5 * time.Second):
		t.Fatal("start not reached")
	}
	if c.launchMu.TryLock() {
		c.launchMu.Unlock()
		close(proceed)
		t.Fatal("final Docker start is outside cancellation fence")
	}
	cancel := storetest.Encode(t, "HostCommand", map[string]any{"commandId": "cancel-concurrent", "kind": "cancel", "executionId": e.Identity.ExecutionID, "generation": "1"})
	accepted := make(chan error, 1)
	go func() { _, err := c.accept(context.Background(), cancel); accepted <- err }()
	select {
	case err := <-accepted:
		close(proceed)
		t.Fatal("cancellation accepted inside committed start boundary", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	if r.starts != 1 {
		t.Fatal("attempt repeated or lost")
	}
	// The concurrent cancellation now wins the next turn: durable cleanup before
	// stop, and no removal/release until SaaS supplies the cleanup command.
	_ = c.execution(context.Background(), current(t, c))
	if r.stops != 1 || r.removes != 0 || !current(t, c).CleanupPending {
		t.Fatal("accepted cancellation was not contained durably")
	}
}
