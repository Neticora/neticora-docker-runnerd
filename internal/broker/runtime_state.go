package broker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

type Lookup struct {
	ExecutionID string `json:"executionId"`
	Generation  string `json:"generation"`
	SpecHash    string `json:"specHash"`
	ResourceID  string `json:"resourceId"`
	RecoveryID  string `json:"recoveryId,omitempty"`
}
type RuntimeState struct {
	Revision   string                           `json:"revision"`
	Phase      string                           `json:"phase"`
	Object     *dockerengine.Object             `json:"object,omitempty"`
	Operations map[string]ExecutionGrantRequest `json:"operations,omitempty"`
	RecoveryID string                           `json:"recoveryId,omitempty"`
}

func (q Lookup) valid() bool {
	r := ExecutionGrantRequest{Version: ExecutionGrantVersion, Operation: "PrepareImage", ExecutionID: q.ExecutionID, Generation: q.Generation, ExpectedRevision: "0", Challenge: "0000000000000000000000000000000000000000000000000000000000000000"}
	r.OperationID = r.OperationIdentity()
	return r.Validate() == nil && digest(q.SpecHash) && (q.ResourceID == "" || digest(q.ResourceID)) && (q.RecoveryID == "" || digest(q.RecoveryID))
}

// load owns no runtime mutation authority. v1 prototype records are retained and
// rejected rather than silently adopted or regenerated during migration.
func (e *physicalExecutor) load(q Lookup) (physicalRecord, dockerengine.Plan, error) {
	s, p, err := e.loadOriginal(q)
	if err == nil && (s.Boot != e.boot || e.recoveryOnly) {
		return s, p, ErrBootRecovery
	}
	return s, p, err
}
func (e *physicalExecutor) loadOriginal(q Lookup) (physicalRecord, dockerengine.Plan, error) {
	var state physicalRecord
	if !q.valid() {
		return state, dockerengine.Plan{}, ErrRejected
	}
	b := e.scope
	b.ExecutionID = q.ExecutionID
	b.Generation = q.Generation
	root, err := e.ledger.records("resources")
	if err != nil {
		return state, dockerengine.Plan{}, err
	}
	defer root.Close()
	if err = readRecord(root, recordID(b), &state); err != nil {
		return state, dockerengine.Plan{}, err
	}
	raw, err := json.Marshal(state.Spec)
	hash, hashErr := protocol.PayloadHashJSON("ExecutionSpec", raw)
	if err != nil || hashErr != nil || hash != state.Spec.SpecHash || protocol.ValidateInboundJSON("ExecutionSpec", raw) != nil {
		return state, dockerengine.Plan{}, ErrQuarantined
	}
	b = state.Binding
	if state.Spec.ExecutionId != b.ExecutionID || state.Spec.Generation != b.Generation {
		return state, dockerengine.Plan{}, ErrQuarantined
	}
	if state.Version != "runnerd-broker-resource-v2" || b.InstallationID != e.scope.InstallationID || b.TenantID != e.scope.TenantID || b.HostID != e.scope.HostID || b.SessionEpoch != e.scope.SessionEpoch || b.EndpointIdentity != e.scope.EndpointIdentity || b.ExecutionID != q.ExecutionID || b.Generation != q.Generation || b.SpecHash != q.SpecHash || b.SpecHash != state.Spec.SpecHash || b.AttemptID != state.Spec.AttemptId || state.Boot == "" || state.Operations == nil || state.Completed == nil || !counter(state.Revision) || !validPhysicalState(state.State) {
		return state, dockerengine.Plan{}, ErrQuarantined
	}
	if q.ResourceID != "" && state.ResourceID != "" && state.ResourceID != q.ResourceID {
		return state, dockerengine.Plan{}, ErrConflict
	}
	revision, _ := strconv.ParseUint(state.Revision, 10, 64)
	if revision != uint64(len(state.Completed)) || len(state.Operations) > 16 || len(state.Completed) > len(state.Operations) || (state.Pending != "" && state.Completed[state.Pending]) ||
		(state.ResourceID != "" && !digest(state.ResourceID)) || ((state.State == "ALLOCATED" || state.State == "NEVER_CREATED") && state.ResourceID != "") ||
		(state.State != "ALLOCATED" && state.State != "NEVER_CREATED" && state.State != "QUARANTINED" && state.ResourceID == "") ||
		((state.State == "STOPPED" || state.State == "REMOVED" || state.State == "NEVER_CREATED") && !state.CancelFence) {
		return state, dockerengine.Plan{}, ErrQuarantined
	}
	pendingFound := state.Pending == ""
	for action, op := range state.Operations {
		if op.Validate() != nil || op.Operation != action || op.ExecutionID != b.ExecutionID || op.Generation != b.Generation || (op.ResourceID != "" && op.ResourceID != state.ResourceID) {
			return state, dockerengine.Plan{}, ErrQuarantined
		}
		if op.OperationID == state.Pending {
			pendingFound = true
		} else if !state.Completed[op.OperationID] {
			return state, dockerengine.Plan{}, ErrQuarantined
		}
	}
	for id, done := range state.Completed {
		if !done || !digest(id) {
			return state, dockerengine.Plan{}, ErrQuarantined
		}
	}
	if !pendingFound {
		return state, dockerengine.Plan{}, ErrQuarantined
	}
	p, err := e.settings.Plan(agent.StoreScope{InstallationID: b.InstallationID, TenantID: b.TenantID, HostID: b.HostID, SessionEpoch: b.SessionEpoch, EndpointIdentity: b.EndpointIdentity}, state.Spec)
	if err != nil || state.Name != p.Name || state.PlanHash != planHash(p) {
		return state, p, ErrQuarantined
	}
	return state, p, nil
}

func (e *physicalExecutor) endpoint(ctx context.Context) error {
	value, err := e.runtime.Probe(ctx)
	if err != nil {
		return err
	}
	expected := e.scope.EndpointIdentity
	if e.recoveryOnly {
		expected = e.runtimeEndpoint
	}
	if value != expected {
		return dockerengine.ErrUnavailable
	}
	return nil
}

// Inspect/reconcile consult the original protected operation. They never issue a
// create/start/stop/remove, renew authority or replace an original resource.
func (e *physicalExecutor) State(ctx context.Context, q Lookup, reconcile bool) (RuntimeState, error) {
	l := e.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	state, p, err := e.loadOriginal(q)
	if os.IsNotExist(err) {
		return RuntimeState{Revision: "0", Phase: "UNALLOCATED"}, dockerengine.ErrAbsent
	}
	if err != nil {
		return RuntimeState{}, err
	}
	if state.Boot != e.boot || e.recoveryOnly {
		record, recoveryErr := e.bootRecord(state)
		result := RuntimeState{Revision: state.Revision, Phase: "BOOT_RECOVERY_REQUIRED", Operations: state.Operations}
		if errors.Is(recoveryErr, ErrBootRecovery) || os.IsNotExist(recoveryErr) || (recoveryErr == nil && record.Phase == "PENDING") {
			return result, ErrBootRecovery
		}
		if recoveryErr != nil {
			return result, recoveryErr
		}
		if err = e.bootAbsent(ctx, state, p, record); err != nil {
			return result, err
		}
		result.Phase = "RECOVERY_DISPOSED"
		result.RecoveryID = record.Authority.Certificate.ID
		return result, dockerengine.ErrAbsent
	}
	if err = e.endpoint(ctx); err != nil {
		return RuntimeState{}, err
	}
	ref := state.ResourceID
	if ref == "" {
		ref = state.Name
	}
	object, inspectErr := e.runtime.Inspect(ctx, ref, p)
	if inspectErr != nil && !errors.Is(inspectErr, dockerengine.ErrAbsent) {
		return RuntimeState{}, inspectErr
	}
	if inspectErr == nil && (!digest(object.ID) || (state.ResourceID != "" && object.ID != state.ResourceID)) {
		return RuntimeState{}, ErrConflict
	}
	if reconcile && state.Pending != "" {
		for action, original := range state.Operations {
			if original.OperationID != state.Pending {
				continue
			}
			phase := ""
			switch action {
			case "DisposeUnstarted":
				if errors.Is(inspectErr, dockerengine.ErrAbsent) && e.unstartedAbsence(ctx, state, p) == nil {
					phase = "NEVER_CREATED"
				}
			case "CreateExecution":
				if inspectErr == nil {
					if object.State == "prepared" {
						phase = "PREPARED"
					} else if object.State == "running" || object.State == "exited" {
						phase = "ACTIVE"
					}
				}
			case "StartExecution":
				if inspectErr == nil && (object.State == "running" || object.State == "exited") {
					phase = "ACTIVE"
				}
			case "StopExecution":
				if inspectErr == nil && object.State != "running" {
					phase = "STOPPED"
				}
			case "RemoveExecution":
				if errors.Is(inspectErr, dockerengine.ErrAbsent) && e.absence(ctx, state, p) == nil {
					phase = "REMOVED"
				}
			}
			if phase == "" {
				return RuntimeState{Revision: state.Revision, Phase: "QUARANTINED", Operations: state.Operations}, ErrQuarantined
			}
			if _, err = l.read(original.OperationID); err != nil {
				return RuntimeState{}, ErrQuarantined
			}
			revision, _ := strconv.ParseUint(state.Revision, 10, 64)
			if revision == ^uint64(0) {
				return RuntimeState{}, ErrConflict
			}
			state.State = phase
			state.ResourceID = object.ID
			if phase == "REMOVED" || phase == "STOPPED" || phase == "NEVER_CREATED" {
				state.ResourceID = original.ResourceID
				state.CancelFence = true
			}
			state.Completed[original.OperationID] = true
			state.Pending = ""
			state.Revision = strconv.FormatUint(revision+1, 10)
			root, e2 := l.records("resources")
			if e2 != nil {
				return RuntimeState{}, e2
			}
			e2 = l.writeRecord(root, recordID(state.Binding), state)
			root.Close()
			if e2 != nil {
				return RuntimeState{}, e2
			}
			break
		}
	}
	result := RuntimeState{Revision: state.Revision, Phase: state.State, Operations: state.Operations}
	if inspectErr == nil {
		result.Object = &object
	}
	if err = e.endpoint(ctx); err != nil {
		return RuntimeState{}, err
	}
	if state.Pending != "" || state.State == "QUARANTINED" {
		return result, ErrQuarantined
	}
	if inspectErr != nil {
		return result, dockerengine.ErrAbsent
	}
	return result, nil
}

func (e *physicalExecutor) unstartedAbsence(ctx context.Context, state physicalRecord, p dockerengine.Plan) error {
	if state.ResourceID != "" || state.Operations["CreateExecution"].OperationID != "" {
		return ErrQuarantined
	}
	if _, err := e.runtime.Inspect(ctx, p.Name, p); !errors.Is(err, dockerengine.ErrAbsent) {
		return ErrQuarantined
	}
	// Full inventory verifies the endpoint and excludes hidden owned resources.
	if _, err := e.runtime.Inventory(ctx); err != nil {
		return err
	}
	if e.handoffs != nil {
		if err := e.handoffs.CheckDisposed(p); err != nil {
			return err
		}
	}
	return e.endpoint(ctx)
}

func (e *physicalExecutor) absence(ctx context.Context, state physicalRecord, p dockerengine.Plan) error {
	if err := e.executionGone(ctx, state, p); err != nil {
		return err
	}
	if e.handoffs != nil {
		if err := e.handoffs.CheckDisposed(p); err != nil {
			return err
		}
	}
	return e.endpoint(ctx)
}

func (e *physicalExecutor) executionGone(ctx context.Context, state physicalRecord, p dockerengine.Plan) error {
	if _, err := e.runtime.Inspect(ctx, state.ResourceID, p); !errors.Is(err, dockerengine.ErrAbsent) {
		return ErrQuarantined
	}
	// A replacement with the deterministic name is an unresolved resource, even
	// when the original immutable ID is absent.
	if _, err := e.runtime.Inspect(ctx, p.Name, p); !errors.Is(err, dockerengine.ErrAbsent) {
		return ErrQuarantined
	}
	ids, err := e.runtime.Inventory(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if id == state.ResourceID {
			return ErrQuarantined
		}
	}
	if net, ok := e.runtime.(interface {
		VerifyNetworkDetached(context.Context, string, string) error
	}); ok {
		if err = net.VerifyNetworkDetached(ctx, state.ResourceID, string(p.HostConfig.NetworkMode)); err != nil {
			return err
		}
	} else if e.handoffs != nil {
		return ErrQuarantined
	}
	return e.endpoint(ctx)
}
