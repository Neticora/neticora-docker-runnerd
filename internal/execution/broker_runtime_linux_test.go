//go:build linux

package execution

import (
	"context"
	"encoding/json"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"strconv"
	"strings"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/internal/broker"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

type acknowledgedBrokerRemote struct{ *fakeRemote }

func (r acknowledgedBrokerRemote) Events(_ context.Context, m protocol.Outbound) ([]protocol.EventAck, error) {
	var batch protocol.EventBatch
	if err := json.Unmarshal(m.Bytes(), &batch); err != nil {
		return nil, err
	}
	last := batch.Events[len(batch.Events)-1]
	return []protocol.EventAck{{ExecutionId: last.ExecutionId, Generation: last.Generation, ContiguousSequence: last.Sequence}}, nil
}

func TestControllerBrokerAdapterPreservesJournalAndLostReplies(t *testing.T) {
	controllerBrokerAdapterRecovery(t, false)
}
func TestControllerBrokerAdapterRecoversBrokerRestartAfterCreate(t *testing.T) {
	controllerBrokerAdapterRecovery(t, true)
}

func TestControllerBrokerCleanupReentryAfterOriginalRemoval(t *testing.T) {
	c, _, _, e := setup(t)
	p, err := c.plan(e)
	if err != nil {
		t.Fatal(err)
	}
	b := &brokerRuntime{controller: c, socket: "/run/test-broker.sock"}
	b.call = func(_ context.Context, _ string, q broker.Request) (broker.Response, error) {
		if q.Operation != "ReconcileExecution" {
			t.Fatal("cleanup reentry acquired new authority", q.Operation)
		}
		return broker.Response{Version: broker.Version, Code: "resource_absent", Runtime: &broker.RuntimeState{Revision: "5", Phase: "REMOVED", Operations: map[string]broker.ExecutionGrantRequest{"StopExecution": {OperationID: strings.Repeat("a", 64)}, "RemoveExecution": {OperationID: strings.Repeat("b", 64)}}}}, broker.ErrRejected
	}
	b.execute = func(context.Context, string, broker.ExecutionGrantRequest) error {
		t.Fatal("completed removal requested a new grant")
		return ErrReconcile
	}
	id := strings.Repeat("c", 64)
	if err = b.Stop(context.Background(), id, p); err != nil {
		t.Fatal(err)
	}
	if err = b.Remove(context.Background(), id, p); err != nil {
		t.Fatal(err)
	}
}
func TestControllerBrokerBootClosureNeverAcquiresLaunchAuthority(t *testing.T) {
	c, _, _, e := setup(t)
	p, err := c.plan(e)
	if err != nil {
		t.Fatal(err)
	}
	b := &brokerRuntime{controller: c, socket: "/run/test-broker.sock"}
	b.call = func(_ context.Context, _ string, q broker.Request) (broker.Response, error) {
		if q.Operation != "ReconcileExecution" {
			t.Fatal("new mutation requested", q.Operation)
		}
		return broker.Response{Version: broker.Version, Code: "resource_absent", Runtime: &broker.RuntimeState{Revision: "1", Phase: "RECOVERY_DISPOSED", RecoveryID: strings.Repeat("f", 64)}}, broker.ErrRejected
	}
	b.execute = func(context.Context, string, broker.ExecutionGrantRequest) error {
		t.Fatal("new authority acquired")
		return ErrReconcile
	}
	if err = b.VerifyKataAbsence(context.Background(), strings.Repeat("c", 64), p); err != nil {
		t.Fatal("verified recovery closure blocked cleanup", err)
	}
	if _, err = b.perform(context.Background(), "CreateExecution", "", p); err == nil {
		t.Fatal("recovery became create")
	}
	if _, err = b.perform(context.Background(), "StartExecution", strings.Repeat("c", 64), p); err == nil {
		t.Fatal("recovery became start")
	}
	if _, err = b.perform(context.Background(), "DisposeUnstarted", "", p); err != nil {
		t.Fatal(err)
	}
}
func controllerBrokerAdapterRecovery(t *testing.T, restart bool) {
	c, _, remote, e := setup(t)
	c.Remote = acknowledgedBrokerRemote{remote}
	state := broker.RuntimeState{Revision: "0", Phase: "UNALLOCATED", Operations: map[string]broker.ExecutionGrantRequest{}}
	counts := map[string]int{}
	outage := false
	b := &brokerRuntime{controller: c, socket: "/run/test-broker.sock"}
	b.call = func(_ context.Context, _ string, q broker.Request) (broker.Response, error) {
		if q.ExecutionGrant != nil || q.ExecutionCommit != nil || q.Authorization != nil || q.Target != "" {
			t.Fatal("observation acquired mutation authority")
		}
		r := broker.Response{Version: broker.Version, Runtime: &state}
		switch q.Operation {
		case "ReadRegistration":
			r.Code = "resource_absent"
			return r, broker.ErrRejected
		case "ReconcileExecution":
			if outage {
				return broker.Response{Version: broker.Version}, dockerengine.ErrUnavailable
			}
			if q.Lookup == nil || q.Lookup.ExecutionID != e.Identity.ExecutionID || q.Lookup.SpecHash != e.Identity.SpecHash {
				t.Fatal("lookup lost original identity")
			}
			if state.Object == nil {
				r.Code = "resource_absent"
				return r, broker.ErrRejected
			}
		case "ProbeRuntime":
			r.Endpoint = c.Scope.EndpointIdentity
		case "GetRuntimeInventory":
			r.Inventory = []string{}
			if state.Object != nil {
				r.Inventory = append(r.Inventory, state.Object.ID)
			}
		case "CheckRuntimeHeadroom":
		default:
			t.Fatalf("unexpected adapter call %s", q.Operation)
		}
		return r, nil
	}
	b.execute = func(_ context.Context, _ string, r broker.ExecutionGrantRequest) error {
		if r.OperationID != r.OperationIdentity() || r.Challenge != "" || r.ExecutionID != e.Identity.ExecutionID || r.Generation != e.Identity.Generation || r.ExpectedRevision != state.Revision {
			t.Fatal("operation identity changed")
		}
		if _, exists := state.Operations[r.Operation]; exists {
			t.Fatal("new authority requested for existing effect")
		}
		counts[r.Operation]++
		state.Operations[r.Operation] = r
		revision, _ := strconv.Atoi(state.Revision)
		state.Revision = strconv.Itoa(revision + 1)
		switch r.Operation {
		case "PrepareImage":
			state.Phase = "ALLOCATED"
		case "CreateExecution":
			// Native claim must precede the broker create, even with a lost reply.
			if err := c.Store.VerifyCreationClaim(context.Background(), c.Scope, e.Command); err != nil {
				t.Fatal(err)
			}
			state.Phase = "PREPARED"
			state.Object = &dockerengine.Object{ID: strings.Repeat("c", 64), State: "prepared"}
			outage = restart
		case "StartExecution":
			fresh := current(t, c)
			if fresh.AckSequence != "1" {
				t.Fatal("prepared observation not acknowledged before grant")
			}
			state.Phase = "ACTIVE"
			state.Object.State = "running"
		default:
			t.Fatal(r.Operation)
		}
		return dockerengine.ErrUnavailable // Effect succeeded; transport lost reply.
	}
	c.Runtime = b
	first := c.execution(context.Background(), e)
	if restart {
		if first == nil {
			t.Fatal("broker outage did not interrupt original create reply")
		}
		outage = false
		for i := 0; i < 2; i++ {
			if err := c.execution(context.Background(), current(t, c)); err != nil {
				t.Fatal(err)
			}
		}
	} else if first != nil {
		t.Fatal(first)
	}
	e = current(t, c)
	if e.State != "running" || e.LastSequence != "2" || counts["CreateExecution"] != 1 || counts["StartExecution"] != 1 {
		t.Fatal("launch journal/order lost", e.State, counts)
	}
	if err := c.execution(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if counts["CreateExecution"] != 1 || counts["StartExecution"] != 1 {
		t.Fatal("retry replaced original")
	}
}
