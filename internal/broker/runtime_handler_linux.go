//go:build linux

package broker

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

func (h handler) runtimeRequest(w http.ResponseWriter, r *http.Request, q Request) bool {
	switch q.Operation {
	case "ProbeRuntime", "GetRuntimeInventory", "GetExecutionStatus", "ReconcileExecution", "ReadRegistration", "CheckRuntimeHeadroom", "ExecuteOperation", "AttestDisposal", "ResumeDisposal", "GetBootRecoveryChallenge", "RecoverBootExecution":
	default:
		return false
	}
	respond := func(status int, value Response) {
		value.Version = Version
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(value)
	}
	fail := func(err error, value *RuntimeState) {
		code, status := "reconciliation_required", 503
		if errors.Is(err, ErrBootRecovery) {
			code, status = "boot_recovery_required", 409
		}
		if errors.Is(err, dockerengine.ErrAbsent) || os.IsNotExist(err) {
			code, status = "resource_absent", 404
		}
		if errors.Is(err, ErrRejected) || errors.Is(err, ErrConflict) || errors.Is(err, dockerengine.ErrConflict) {
			code, status = "operation_rejected", 403
		}
		if errors.Is(err, dockerengine.ErrStoragePressure) {
			code, status = "storage_pressure", 409
		}
		if status != 404 {
			slog.Warn("broker runtime operation held", "operation", q.Operation, "code", code, "error", err)
		}
		respond(status, Response{Code: code, Runtime: value})
	}
	if h.executor == nil {
		respond(400, Response{Code: "unsupported_operation"})
		return true
	}
	e := h.executor
	if q.Target != "" || q.Authorization != nil {
		fail(ErrRejected, nil)
		return true
	}
	if q.Operation == "GetBootRecoveryChallenge" || q.Operation == "RecoverBootExecution" {
		if q.MinimumFreeBytes != 0 || q.ExecutionRequest != nil || q.ExecutionGrant != nil || q.ExecutionCommit != nil || q.DisposalChallenge != nil {
			fail(ErrRejected, nil)
			return true
		}
		if q.Operation == "GetBootRecoveryChallenge" {
			if q.Lookup == nil || q.BootCertificate != nil {
				fail(ErrRejected, nil)
				return true
			}
			challenge, err := e.IssueBootChallenge(r.Context(), *q.Lookup, h.disposalKey)
			if err != nil {
				fail(err, nil)
				return true
			}
			respond(200, Response{Code: "boot_challenge_issued", BootChallenge: &challenge})
			return true
		}
		if q.Lookup != nil || q.BootCertificate == nil {
			fail(ErrRejected, nil)
			return true
		}
		if err := e.RecoverBoot(r.Context(), *q.BootCertificate); err != nil {
			fail(err, nil)
			return true
		}
		respond(200, Response{Code: "boot_cleanup_observed"})
		return true
	}
	if q.BootCertificate != nil {
		fail(ErrRejected, nil)
		return true
	}
	if q.Operation == "AttestDisposal" {
		if q.Lookup != nil || q.MinimumFreeBytes != 0 || q.ExecutionRequest != nil || q.ExecutionGrant != nil || q.ExecutionCommit != nil || q.DisposalChallenge == nil {
			fail(ErrRejected, nil)
			return true
		}
		proof, err := e.Attest(r.Context(), *q.DisposalChallenge, h.disposalKey)
		if err != nil {
			fail(err, nil)
			return true
		}
		respond(200, Response{Code: "disposal_observed", Disposal: &proof})
		return true
	}
	if q.DisposalChallenge != nil {
		fail(ErrRejected, nil)
		return true
	}
	if q.Operation == "ExecuteOperation" {
		if q.Lookup != nil || q.MinimumFreeBytes != 0 || q.ExecutionRequest == nil || q.ExecutionGrant == nil || q.ExecutionCommit == nil {
			fail(ErrRejected, nil)
			return true
		}
		_, err := e.Execute(r.Context(), *q.ExecutionRequest, *q.ExecutionGrant, *q.ExecutionCommit)
		if err != nil {
			fail(err, nil)
			return true
		}
		lookup := Lookup{ExecutionID: q.ExecutionRequest.ExecutionID, Generation: q.ExecutionRequest.Generation, SpecHash: q.ExecutionGrant.Grant.Binding.SpecHash}
		state, err := e.State(r.Context(), lookup, false)
		if err != nil && !errors.Is(err, dockerengine.ErrAbsent) {
			fail(err, &state)
			return true
		}
		respond(200, Response{Code: "operation_completed", Runtime: &state})
		return true
	}
	if q.ExecutionGrant != nil || q.ExecutionCommit != nil || q.ExecutionRequest != nil {
		fail(ErrRejected, nil)
		return true
	}
	if q.Operation == "ProbeRuntime" || q.Operation == "GetRuntimeInventory" || q.Operation == "CheckRuntimeHeadroom" {
		if q.Lookup != nil {
			fail(ErrRejected, nil)
			return true
		}
		if err := e.endpoint(r.Context()); err != nil {
			fail(err, nil)
			return true
		}
		switch q.Operation {
		case "ProbeRuntime":
			respond(200, Response{Code: "runtime_observed", Endpoint: e.scope.EndpointIdentity})
		case "GetRuntimeInventory":
			ids, err := e.runtime.Inventory(r.Context())
			if err != nil {
				fail(err, nil)
				return true
			}
			if err = e.endpoint(r.Context()); err != nil {
				fail(err, nil)
				return true
			}
			if ids == nil {
				ids = []string{}
			}
			respond(200, Response{Code: "inventory_observed", Endpoint: e.scope.EndpointIdentity, Inventory: ids})
		case "CheckRuntimeHeadroom":
			engine, ok := e.runtime.(interface {
				CheckHeadroom(context.Context, uint64) error
			})
			if !ok {
				fail(ErrRejected, nil)
				return true
			}
			if err := engine.CheckHeadroom(r.Context(), q.MinimumFreeBytes); err != nil {
				fail(err, nil)
				return true
			}
			respond(200, Response{Code: "headroom_observed"})
		}
		return true
	}
	if q.Lookup == nil || !q.Lookup.valid() || q.MinimumFreeBytes != 0 {
		fail(ErrRejected, nil)
		return true
	}
	if q.Operation == "ReadRegistration" {
		e.ledger.mu.Lock()
		state, p, err := e.load(*q.Lookup)
		var raw []byte
		if err == nil && e.handoffs != nil {
			raw, err = e.handoffs.Registration(p)
		} else if err == nil {
			err = ErrRejected
		}
		e.ledger.mu.Unlock()
		_ = state
		if err != nil {
			fail(err, nil)
			return true
		}
		respond(200, Response{Code: "registration_observed", Registration: raw})
		return true
	}
	if q.Operation == "ResumeDisposal" {
		if err := e.ResumeDisposal(r.Context(), *q.Lookup); err != nil {
			fail(err, nil)
			return true
		}
	}
	state, err := e.State(r.Context(), *q.Lookup, q.Operation == "ReconcileExecution")
	if err != nil {
		fail(err, &state)
		return true
	}
	respond(200, Response{Code: "execution_observed", Runtime: &state})
	return true
}
