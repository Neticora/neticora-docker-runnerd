package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

var ErrQuarantined = errors.New("broker physical resource requires reconciliation; retain ownership")

// Runtime construction is restricted to the explicitly tagged qualification
// build. Production activation awaits the complete qualification campaign.
type physicalRuntime interface {
	Probe(context.Context) (string, error)
	PrepareImageAuthorized(context.Context, dockerengine.Plan, func() error) error
	Inspect(context.Context, string, dockerengine.Plan) (dockerengine.Object, error)
	Ensure(context.Context, dockerengine.Plan, func() error) (dockerengine.Object, error)
	Start(context.Context, string, dockerengine.Plan, func() error) (dockerengine.Object, error)
	Stop(context.Context, string, dockerengine.Plan) error
	Remove(context.Context, string, dockerengine.Plan) error
	Inventory(context.Context) ([]string, error)
}

var _ physicalRuntime = (*dockerengine.Engine)(nil)

type physicalExecutor struct {
	kata            kataLifecycle
	ledger          *Ledger
	runtime         physicalRuntime
	key             ed25519.PublicKey
	scope           Binding
	settings        standardlinux.Settings // Protected local configuration, never IPC input.
	policy          *standardlinux.Policy
	verifyImage     func(context.Context, protocol.ExecutionSpec) error
	guardMounts     func(context.Context, dockerengine.Plan) error
	boot            string
	now             func() time.Time
	handoffs        *handoffManager
	checkpoint      func(string, ExecutionGrantRequest) error // Qualification-only crash boundary.
	recoveryOnly    bool
	runtimeEndpoint string
}

type physicalRecord struct {
	Version      string                           `json:"version"`
	Binding      Binding                          `json:"binding"`
	Boot         string                           `json:"boot"`
	EngineAnchor string                           `json:"engineAnchor,omitempty"`
	PlanHash     string                           `json:"planHash"`
	Name         string                           `json:"name"`
	ResourceID   string                           `json:"resourceId"`
	State        string                           `json:"state"`
	Revision     string                           `json:"revision"`
	CancelFence  bool                             `json:"cancelFence"`
	Pending      string                           `json:"pending"`
	Completed    map[string]bool                  `json:"completed"`
	Spec         protocol.ExecutionSpec           `json:"spec"`
	Operations   map[string]ExecutionGrantRequest `json:"operations"`
}

func recordID(b Binding) string {
	raw, _ := canonical([]string{b.InstallationID, b.TenantID, b.HostID, b.ExecutionID, b.Generation})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func planHash(p dockerengine.Plan) string {
	raw, err := canonical(p)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func validPhysicalState(s string) bool {
	switch s {
	case "ALLOCATED", "PREPARED", "ACTIVE", "STOPPED", "REMOVED", "NEVER_CREATED", "QUARANTINED":
		return true
	}
	return false
}

func (e *physicalExecutor) Execute(ctx context.Context, r ExecutionGrantRequest, s SignedExecutionGrant, c SignedCommit) (dockerengine.Object, error) {
	if e.recoveryOnly {
		return dockerengine.Object{}, ErrRejected
	}
	if e.ledger == nil || e.runtime == nil || e.policy == nil || e.now == nil || e.boot == "" || e.verifyImage == nil || e.guardMounts == nil {
		return dockerengine.Object{}, ErrRejected
	}
	if e.policy.UID() != e.settings.RunnerUID {
		return dockerengine.Object{}, ErrRejected
	}
	now := e.now()
	if VerifyExecutionGrant(s, r, e.key, e.scope, now) != nil || verifyCommit(c, s, e.key, now) != nil {
		return dockerengine.Object{}, ErrRejected
	}
	// Freshness gates initiation. Once begun, the exact committed effect retains
	// the existing runtime/caller deadline; expiry never mints another operation.
	spec := s.Grant.Spec
	scope := agent.StoreScope{InstallationID: e.scope.InstallationID, TenantID: e.scope.TenantID, HostID: e.scope.HostID, SessionEpoch: e.scope.SessionEpoch, EndpointIdentity: e.scope.EndpointIdentity}
	p, err := e.plan(scope, spec)
	if err != nil || planHash(p) == "" {
		return dockerengine.Object{}, ErrRejected
	}
	l := e.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed {
		return dockerengine.Object{}, ErrRejected
	}
	root, err := l.records("resources")
	if err != nil {
		return dockerengine.Object{}, err
	}
	defer root.Close()
	id := recordID(s.Grant.Binding)
	var state physicalRecord
	err = readRecord(root, id, &state)
	if os.IsNotExist(err) {
		if r.ExpectedRevision != "0" || (r.Operation != "PrepareImage" && r.Operation != "CreateExecution" && r.Operation != "DisposeUnstarted") {
			return dockerengine.Object{}, ErrQuarantined
		}
		state = physicalRecord{Version: "runnerd-broker-resource-v2", Binding: s.Grant.Binding, Boot: e.boot, PlanHash: planHash(p), Name: p.Name, State: "ALLOCATED", Revision: "0", Completed: map[string]bool{}, Spec: spec, Operations: map[string]ExecutionGrantRequest{}}
		if engine, ok := e.runtime.(interface {
			RecoveryDomain(context.Context) (string, error)
		}); ok {
			anchor, anchorErr := engine.RecoveryDomain(ctx)
			if anchorErr != nil || !digest(anchor) {
				return dockerengine.Object{}, ErrQuarantined
			}
			state.EngineAnchor = anchor
		}
	} else if err != nil {
		return dockerengine.Object{}, err
	}
	if state.Version != "runnerd-broker-resource-v2" || state.Binding != s.Grant.Binding || state.Boot != e.boot || state.PlanHash != planHash(p) || state.Name != p.Name || !counter(state.Revision) || !validPhysicalState(state.State) || state.Completed == nil || len(state.Completed) > 16 || state.Operations == nil || state.Spec.SpecHash != spec.SpecHash {
		return dockerengine.Object{}, ErrQuarantined
	}
	storedRevision, _ := strconv.ParseUint(state.Revision, 10, 64)
	if storedRevision != uint64(len(state.Completed)) || (state.Pending != "" && !digest(state.Pending)) ||
		(state.ResourceID != "" && !digest(state.ResourceID)) ||
		(state.State == "ALLOCATED" && state.ResourceID != "") ||
		(state.State != "ALLOCATED" && state.State != "NEVER_CREATED" && state.State != "QUARANTINED" && state.ResourceID == "") ||
		((state.State == "STOPPED" || state.State == "REMOVED" || state.State == "NEVER_CREATED") && !state.CancelFence) {
		return dockerengine.Object{}, ErrQuarantined
	}
	for operation, done := range state.Completed {
		if !digest(operation) || !done {
			return dockerengine.Object{}, ErrQuarantined
		}
	}
	if state.State == "QUARANTINED" || state.Pending != "" {
		return dockerengine.Object{}, ErrQuarantined
	}
	if state.Completed[r.OperationID] {
		// Historical progress only. Replaying a completed grant cannot run a
		// callback, reopen a challenge or repeat the physical effect.
		return dockerengine.Object{ID: state.ResourceID, State: state.State}, nil
	}
	if original, ok := state.Operations[r.Operation]; ok && original.OperationID != r.OperationID {
		return dockerengine.Object{}, ErrConflict
	}
	if state.Revision != r.ExpectedRevision || (r.ResourceID != "" && r.ResourceID != state.ResourceID) || (state.CancelFence && (r.Operation == "StartExecution" || r.Operation == "CreateExecution" || r.Operation == "PrepareImage")) {
		return dockerengine.Object{}, ErrConflict
	}
	allowed := false
	switch r.Operation {
	case "PrepareImage", "CreateExecution":
		allowed = state.State == "ALLOCATED" && state.ResourceID == ""
	case "StartExecution":
		allowed = state.State == "PREPARED" && digest(state.ResourceID)
	case "StopExecution":
		allowed = (state.State == "ACTIVE" || state.State == "PREPARED" || state.State == "STOPPED") && digest(state.ResourceID)
	case "RemoveExecution":
		allowed = state.State == "STOPPED" && digest(state.ResourceID)
	case "DisposeUnstarted":
		_, created := state.Operations["CreateExecution"]
		allowed = state.State == "ALLOCATED" && state.ResourceID == "" && !created
	}
	if !allowed {
		return dockerengine.Object{}, ErrConflict
	}
	guard := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if VerifyExecutionGrant(s, r, e.key, e.scope, e.now()) != nil || verifyCommit(c, s, e.key, e.now()) != nil {
			return ErrRejected
		}
		if err := l.checkLaunchFence(r, state.Binding); err != nil {
			return err
		}
		endpoint, err := e.runtime.Probe(ctx)
		if err != nil || endpoint != state.Binding.EndpointIdentity {
			return dockerengine.ErrUnavailable
		}
		if r.Operation == "PrepareImage" || r.Operation == "CreateExecution" || r.Operation == "StartExecution" {
			if err = e.admit(ctx, scope, spec); err != nil {
				return err
			}
			if err = e.verifyImage(ctx, spec); err != nil {
				return err
			}
			if r.Operation != "PrepareImage" {
				if err = e.guardMounts(ctx, p); err != nil {
					return err
				}
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if VerifyExecutionGrant(s, r, e.key, e.scope, e.now()) != nil || verifyCommit(c, s, e.key, e.now()) != nil {
			return ErrRejected
		}
		return nil
	}
	if err = guard(); err != nil {
		return dockerengine.Object{}, err
	}
	// A matching pre-existing container with no protected creation intent is
	// foreign/legacy, even if its labels/configuration look plausible.
	if r.Operation == "CreateExecution" {
		if _, err = e.runtime.Inspect(ctx, p.Name, p); !errors.Is(err, dockerengine.ErrAbsent) {
			state.State = "QUARANTINED"
			if writeErr := l.writeRecord(root, id, state); writeErr != nil {
				return dockerengine.Object{}, writeErr
			}
			return dockerengine.Object{}, ErrQuarantined
		}
	}
	if r.ResourceID != "" {
		object, inspectErr := e.runtime.Inspect(ctx, state.ResourceID, p)
		if inspectErr != nil && !errors.Is(inspectErr, dockerengine.ErrAbsent) {
			return dockerengine.Object{}, inspectErr
		}
		if inspectErr == nil && object.ID != state.ResourceID {
			return dockerengine.Object{}, ErrConflict
		}
		if r.Operation == "StartExecution" && (inspectErr != nil || object.State != "prepared") {
			return dockerengine.Object{}, ErrConflict
		}
		if r.Operation == "RemoveExecution" && inspectErr == nil && object.State == "running" {
			return dockerengine.Object{}, ErrConflict
		}
	}
	payload, err := s.Grant.IntentPayload()
	if err != nil {
		return dockerengine.Object{}, err
	}
	if consumed, consumeErr := l.consumeChallenge(s, r, c, e.key, e.now()); consumeErr != nil || consumed {
		if consumeErr != nil {
			return dockerengine.Object{}, consumeErr
		}
		return dockerengine.Object{}, ErrQuarantined
	}
	if _, duplicate, err := l.begin(r.OperationID, r.Operation, state.Binding, payload); err != nil || duplicate {
		if err != nil {
			return dockerengine.Object{}, err
		}
		// An accepted-only or interrupted intent is not fresh effect authority.
		return dockerengine.Object{}, ErrQuarantined
	}
	state.Pending = r.OperationID
	state.Operations[r.Operation] = r
	if r.Operation == "StopExecution" || r.Operation == "RemoveExecution" || r.Operation == "DisposeUnstarted" {
		state.CancelFence = true
	}
	if err = l.writeRecord(root, id, state); err != nil {
		return dockerengine.Object{}, err
	}
	quarantine := func(cause error) (dockerengine.Object, error) {
		state.State = "QUARANTINED"
		_ = l.writeRecord(root, id, state)
		return dockerengine.Object{}, errors.Join(ErrQuarantined, cause)
	}
	if err = guard(); err != nil {
		return quarantine(err)
	}
	if e.checkpoint != nil {
		if err = e.checkpoint("before-effect", r); err != nil {
			return quarantine(err)
		}
	}
	var object dockerengine.Object
	switch r.Operation {
	case "DisposeUnstarted":
		if e.handoffs != nil {
			err = e.handoffs.DisposeUnstarted(p)
		}
		if err == nil {
			err = e.unstartedAbsence(ctx, state, p)
		}
		if err == nil {
			state.State = "NEVER_CREATED"
		}
	case "PrepareImage":
		err = e.runtime.PrepareImageAuthorized(ctx, p, guard)
	case "CreateExecution":
		if e.kata != nil {
			err = e.kata.Prepare(ctx, p)
		}
		if err == nil {
			object, err = e.runtime.Ensure(ctx, p, guard)
		}
		if err == nil && e.kata != nil {
			err = e.kata.Prepared(object.ID, p)
		}
		if err == nil && (!digest(object.ID) || object.State != "prepared") {
			err = ErrConflict
		}
		if err == nil {
			state.ResourceID = object.ID
			state.State = "PREPARED"
		}
	case "StartExecution":
		if e.kata != nil {
			err = e.kata.VerifyStorage(ctx, p)
		}
		if err == nil {
			object, err = e.runtime.Start(ctx, state.ResourceID, p, guard)
		}
		if err == nil && e.kata != nil {
			err = e.kata.Capture(ctx, state.ResourceID, p)
		}
		if err == nil && (object.ID != state.ResourceID || (object.State != "running" && object.State != "exited")) {
			err = ErrConflict
		}
		if err == nil {
			state.State = "ACTIVE"
		}
	case "StopExecution":
		if e.kata != nil {
			current, inspectErr := e.runtime.Inspect(ctx, state.ResourceID, p)
			if inspectErr != nil {
				err = inspectErr
			} else if current.State == "running" {
				err = e.kata.Capture(ctx, state.ResourceID, p)
			} else if current.State == "prepared" {
				err = e.kata.Prepared(state.ResourceID, p)
			}
		}
		if err == nil {
			err = e.runtime.Stop(ctx, state.ResourceID, p)
		}
		if err == nil {
			object, err = e.runtime.Inspect(ctx, state.ResourceID, p)
			if errors.Is(err, dockerengine.ErrAbsent) {
				err = nil
			} else if err == nil && (object.ID != state.ResourceID || object.State == "running") {
				err = ErrConflict
			}
		}
		if err == nil {
			state.State = "STOPPED"
		}
	case "RemoveExecution":
		err = e.runtime.Remove(ctx, state.ResourceID, p)
		if err == nil && e.checkpoint != nil {
			err = e.checkpoint("after-effect", r)
		}
		if err == nil {
			if _, inspectErr := e.runtime.Inspect(ctx, state.ResourceID, p); !errors.Is(inspectErr, dockerengine.ErrAbsent) {
				err = ErrQuarantined
			}
		}
		if err == nil {
			var ids []string
			ids, err = e.runtime.Inventory(ctx)
			for _, observed := range ids {
				if observed == state.ResourceID {
					err = ErrQuarantined
				}
			}
		}
		if err == nil {
			err = e.endpoint(ctx)
		}
		if err == nil && e.kata != nil {
			err = e.kata.Dispose(ctx, state.ResourceID, p, func() error { return e.executionGone(ctx, state, p) })
		}
		if err == nil && e.handoffs != nil {
			err = e.handoffs.Dispose(p)
		}
		if err == nil {
			err = e.absence(ctx, state, p)
		}
		if err == nil {
			state.State = "REMOVED"
		}
	}
	if err == nil && e.checkpoint != nil && r.Operation != "RemoveExecution" {
		err = e.checkpoint("after-effect", r)
	}
	if err != nil {
		return quarantine(err)
	}
	revision, err := strconv.ParseUint(state.Revision, 10, 64)
	if err != nil || revision == ^uint64(0) {
		return quarantine(ErrConflict)
	}
	state.Revision = strconv.FormatUint(revision+1, 10)
	state.Pending = ""
	state.Completed[r.OperationID] = true
	if err = l.writeRecord(root, id, state); err != nil {
		return dockerengine.Object{}, err
	}
	// REMOVED is container-specific evidence only, never native CLEANED, final
	// ACK, guest-storage disposal or permission to release a platform reservation.
	return dockerengine.Object{ID: state.ResourceID, State: state.State}, nil
}
