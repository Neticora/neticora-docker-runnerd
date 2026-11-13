package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

// ResumeDisposal finishes only private handoff teardown for an original consumed
// removal intent. It cannot issue any Docker mutation or authorize new work.
func (e *physicalExecutor) ResumeDisposal(ctx context.Context, q Lookup) error {
	l := e.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	state, p, err := e.load(q)
	if err != nil {
		return err
	}
	if state.Pending == "" || !state.CancelFence {
		return ErrRejected
	}
	var original ExecutionGrantRequest
	for _, op := range state.Operations {
		if op.OperationID == state.Pending {
			original = op
			break
		}
	}
	if original.Operation != "RemoveExecution" && original.Operation != "DisposeUnstarted" {
		return ErrRejected
	}
	if original.ExpectedRevision != state.Revision || state.Completed[original.OperationID] {
		return ErrQuarantined
	}
	receipt, err := l.read(original.OperationID)
	if err != nil {
		return err
	}
	payload, err := (ExecutionGrant{Version: ExecutionGrantVersion, Operation: original.Operation, OperationID: original.OperationID, ExpectedRevision: original.ExpectedRevision, ExpectedState: executionState(original.Operation), ResourceID: original.ResourceID, Binding: state.Binding, Spec: state.Spec}).IntentPayload()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	if receipt.Operation != original.Operation || receipt.Binding != state.Binding || receipt.PayloadHash != hex.EncodeToString(sum[:]) {
		return ErrQuarantined
	}
	// Read the original challenge as well: a historical receipt alone must not
	// promote a foundation-only intent into physical authority.
	root, err := l.records("challenges")
	if err != nil {
		return err
	}
	var challenge Challenge
	err = readRecord(root, original.OperationID, &challenge)
	root.Close()
	if err != nil || challenge.Version != challengeVersion || challenge.State != "CONSUMED" || challenge.Request != original || challenge.Binding == nil || *challenge.Binding != state.Binding || !digest(challenge.GrantHash) {
		return ErrQuarantined
	}
	if original.Operation == "RemoveExecution" {
		if original.ResourceID != state.ResourceID || !digest(state.ResourceID) {
			return ErrQuarantined
		}
		if err = e.executionGone(ctx, state, p); err != nil {
			return err
		}
		if e.kata != nil {
			if err = e.kata.Dispose(ctx, state.ResourceID, p, original.OperationID, func() error { return e.executionGone(ctx, state, p) }); err != nil {
				return err
			}
		}
		if e.handoffs != nil {
			if err = e.handoffs.Dispose(p); err != nil {
				return err
			}
		}
		if err = e.absence(ctx, state, p); err != nil {
			return err
		}
		state.State = "REMOVED"
	} else {
		if state.ResourceID != "" || state.Operations["CreateExecution"].OperationID != "" {
			return ErrQuarantined
		}
		if _, err = e.runtime.Inspect(ctx, p.Name, p); !errors.Is(err, dockerengine.ErrAbsent) {
			return ErrQuarantined
		}
		if err = e.endpoint(ctx); err != nil {
			return err
		}
		if e.handoffs != nil {
			if err = e.handoffs.DisposeUnstarted(p); err != nil {
				return err
			}
		}
		if err = e.unstartedAbsence(ctx, state, p); err != nil {
			return err
		}
		state.State = "NEVER_CREATED"
	}
	revision, _ := strconv.ParseUint(state.Revision, 10, 64)
	if revision == ^uint64(0) {
		return ErrConflict
	}
	state.Completed[original.OperationID] = true
	state.Pending = ""
	state.Revision = strconv.FormatUint(revision+1, 10)
	root, err = l.records("resources")
	if err != nil {
		return err
	}
	defer root.Close()
	return l.writeRecord(root, recordID(state.Binding), state)
}
