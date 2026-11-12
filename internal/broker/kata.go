package broker

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	"time"
)

// Installed only from protected local configuration. IPC supplies identities,
// never a profile, a Docker plan or a block-device path.
type kataLifecycle interface {
	Check(context.Context) (string, error)
	Plan(agent.StoreScope, protocol.ExecutionSpec) (dockerengine.Plan, error)
	Admit(context.Context, agent.StoreScope, protocol.ExecutionSpec, *standardlinux.Policy, time.Time) error
	Prepare(context.Context, dockerengine.Plan) error
	Prepared(string, dockerengine.Plan) error
	VerifyStorage(context.Context, dockerengine.Plan) error
	Capture(context.Context, string, dockerengine.Plan) error
	Healthy(dockerengine.Plan, string, time.Time) bool
	Dispose(context.Context, string, dockerengine.Plan, func() error) error
	Absence(context.Context, string, dockerengine.Plan) error
	Evidence(context.Context, string, dockerengine.Plan) (json.RawMessage, error)
}

func (e *physicalExecutor) plan(scope agent.StoreScope, s protocol.ExecutionSpec) (dockerengine.Plan, error) {
	if s.IsolationProfile == "isolated" {
		if e.kata == nil {
			return dockerengine.Plan{}, ErrRejected
		}
		return e.kata.Plan(scope, s)
	}
	if s.IsolationProfile != "standard" || e.kata != nil {
		return dockerengine.Plan{}, ErrRejected
	}
	return e.settings.Plan(scope, s)
}
func (e *physicalExecutor) admit(ctx context.Context, scope agent.StoreScope, s protocol.ExecutionSpec) error {
	if s.IsolationProfile == "isolated" {
		if e.kata == nil {
			return ErrRejected
		}
		return e.kata.Admit(ctx, scope, s, e.policy, e.now())
	}
	return e.policy.Admit(scope, s, e.now())
}

type kataBootLifecycle interface {
	Evidence(context.Context, string, dockerengine.Plan) (json.RawMessage, error)
	Plan(agent.StoreScope, protocol.ExecutionSpec) (dockerengine.Plan, error)
	Observe(context.Context, string, dockerengine.Plan) error
	RecoverDispose(context.Context, string, dockerengine.Plan, func() error) error
	Absence(context.Context, string, dockerengine.Plan) error
}

func (e *physicalExecutor) bootKata(s physicalRecord) (kataBootLifecycle, error) {
	if s.Spec.IsolationProfile != "isolated" || len(s.KataOrigin) == 0 || e.restoreKata == nil {
		return nil, ErrQuarantined
	}
	return e.restoreKata(s.KataOrigin)
}
func kataRecoveryHash(s physicalRecord) string {
	if s.Spec.IsolationProfile == "isolated" && len(s.KataOrigin) > 0 {
		return bootHash(json.RawMessage(s.KataOrigin))
	}
	return ""
}

// Caller holds the ledger lock. Export cannot complete cleanup or advance native ACKs.
func (e *physicalExecutor) kataEvidence(ctx context.Context, q Lookup) (json.RawMessage, error) {
	state, p, err := e.load(q)
	if state.Spec.IsolationProfile != "isolated" {
		return nil, ErrRejected
	}
	if errors.Is(err, ErrBootRecovery) {
		record, readErr := e.bootRecord(state)
		if readErr != nil {
			return nil, readErr
		}
		if record.Phase != "DISPOSED" {
			return nil, ErrQuarantined
		}
		if err = e.bootAbsent(ctx, state, p, record); err != nil {
			return nil, err
		}
		k, restoreErr := e.bootKata(state)
		if restoreErr != nil {
			return nil, restoreErr
		}
		return k.Evidence(ctx, state.ResourceID, p)
	}
	if err != nil {
		return nil, err
	}
	if e.kata == nil || state.State != "REMOVED" || state.Pending != "" {
		return nil, ErrRejected
	}
	if err = e.absence(ctx, state, p); err != nil {
		return nil, err
	}
	return e.kata.Evidence(ctx, state.ResourceID, p)
}
