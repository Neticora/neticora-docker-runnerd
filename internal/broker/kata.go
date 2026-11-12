package broker

import (
	"context"
	"encoding/json"
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
