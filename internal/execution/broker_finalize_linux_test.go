//go:build linux

package execution

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

type finalizedRuntime struct {
	*fakeRuntime
	closed, verified bool
}

func (f *finalizedRuntime) RecoveryDisposed(context.Context, string, dockerengine.Plan) (bool, error) {
	return f.closed, nil
}
func (f *finalizedRuntime) VerifyDisposal(context.Context, string, dockerengine.Plan) error {
	if !f.closed {
		return ErrReconcile
	}
	f.verified = true
	return nil
}

type finalizationRemote struct {
	*fakeRemote
	runtime *finalizedRuntime
	lose    bool
	ack     string
}

func (f *finalizationRemote) Events(_ context.Context, m protocol.Outbound) ([]protocol.EventAck, error) {
	var batch protocol.EventBatch
	if json.Unmarshal(m.Bytes(), &batch) != nil {
		return nil, ErrReconcile
	}
	for _, e := range batch.Events {
		if e.Observation != nil && e.Observation.State == "cleaned" && !f.runtime.verified {
			return nil, ErrReconcile
		}
	}
	if f.lose {
		f.lose = false
		return nil, errors.New("lost final event acknowledgment")
	}
	last := batch.Events[len(batch.Events)-1]
	f.ack = last.Sequence
	return []protocol.EventAck{{ExecutionId: last.ExecutionId, Generation: last.Generation, ContiguousSequence: last.Sequence}}, nil
}
func TestRecoveryDisposalReentersOriginalCleanupAndFinalAck(t *testing.T) {
	ctx := context.Background()
	c, r, remote, e := setup(t)
	if err := c.execution(ctx, e); err != nil {
		t.Fatal(err)
	}
	original := current(t, c)
	r.object = nil
	recovered := &finalizedRuntime{fakeRuntime: r, closed: true}
	c.Runtime = recovered
	server := &finalizationRemote{fakeRemote: remote, runtime: recovered, lose: true}
	c.Remote = server
	c.recoveryOnly = true
	c.Drained = func() bool { return true }
	cleanup := storetest.Encode(t, "HostCommand", map[string]any{"kind": "cleanup", "commandId": "original-cleanup", "executionId": original.Identity.ExecutionID, "generation": original.Identity.Generation})
	if _, err := c.Store.AcceptCommand(ctx, c.Scope, cleanup); err != nil {
		t.Fatal(err)
	}
	remote.recoveryEntries = []protocol.RecoveryEntry{{ExecutionId: original.Identity.ExecutionID, Generation: original.Identity.Generation, CommandId: original.CommandID, SpecHash: original.Identity.SpecHash, ContiguousSequence: "0", Cancelled: true}}
	if _, err := c.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.execution(ctx, original); err != nil {
		t.Fatal(err)
	}
	cleaned := current(t, c)
	if cleaned.State != "cleaned" || cleaned.CleanupPending || string(cleaned.RuntimeRef) != string(original.RuntimeRef) || string(cleaned.Command) != string(original.Command) {
		t.Fatal("recovery replaced original history", cleaned)
	}
	if !recovered.verified || r.creates != 1 || r.starts != 1 {
		t.Fatal("disposal omitted or workload replaced")
	}
	if err := c.flushExecutionEvents(ctx, original.Identity.ExecutionID, original.Identity.Generation); err == nil {
		t.Fatal("lost ACK accepted")
	}
	pending, err := c.executions(ctx)
	if err != nil || len(pending) != 1 {
		t.Fatal("pending final ACK forgotten", err)
	}
	if err = c.flushExecutionEvents(ctx, original.Identity.ExecutionID, original.Identity.Generation); err != nil {
		t.Fatal(err)
	}
	done := current(t, c)
	if done.LastSequence != "4" || done.AckSequence != "4" {
		t.Fatal("terminal ACK missing", done)
	}
	pending, err = c.executions(ctx)
	if err != nil || len(pending) != 0 {
		t.Fatal("acknowledged original not retired", err)
	}
}
func TestRecoveryOnlyCannotGenerateLaunchPlans(t *testing.T) {
	c, _, _, e := setup(t)
	c.recoveryOnly = true
	start, err := c.storedStart(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.resolvePlan(c.Scope, start.Spec); err == nil {
		t.Fatal("recovery acquired launch plan")
	}
	if err = c.admit(start.Spec, time.Now()); err == nil {
		t.Fatal("recovery admitted work")
	}
	p, err := c.resolveRecoveryPlan(c.Scope, start.Spec)
	if err != nil || !p.RecoveryOnly || p.HostConfig != nil || p.Config.Image != "" || len(p.Config.Entrypoint) != 0 {
		t.Fatal("executable payload in lookup plan", p, err)
	}
}
func TestMissingContainerWithoutRecoveryClosureKeepsNativeObligation(t *testing.T) {
	ctx := context.Background()
	c, r, _, e := setup(t)
	if err := c.execution(ctx, e); err != nil {
		t.Fatal(err)
	}
	original := current(t, c)
	r.object = nil
	c.Runtime = &finalizedRuntime{fakeRuntime: r, closed: false}
	c.cancelled[executionKey(original)] = true
	c.Drained = func() bool { return true }
	if err := c.execution(ctx, original); err == nil {
		t.Fatal("absence inferred completion")
	}
	held := current(t, c)
	if held.State == "cleaned" || held.LastSequence != original.LastSequence {
		t.Fatal("unproven resource released")
	}
}
