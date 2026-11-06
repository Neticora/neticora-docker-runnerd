package dockerengine

import (
	"context"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
	"github.com/moby/moby/client"
)

// RecoveryAuthority is supplied only by the recovery coordinator. Commit verifies
// the exact journal snapshot and durably records approval before returning its
// fresh authenticated platform authorization. Network calls never run in SQLite
// transactions. It is called separately for every targeted mutation; the Engine
// retains no reusable mutation capability and can never create/start in this mode.
type RecoveryAuthority func(context.Context) (*peerrecovery.Authorization, error)

func (e *Engine) recoveryCheck(ctx context.Context, id string, p Plan, authority RecoveryAuthority) error {
	if !e.readOnly || authority == nil || p.Config == nil || p.HostConfig == nil {
		return ErrRecoveryApprovalRequired
	}
	a, err := authority(ctx)
	if err != nil {
		return err
	}
	if !a.Current(time.Now()) {
		return ErrRecoveryApprovalRequired
	}
	value, err := a.Approval().Value()
	if err != nil {
		return ErrRecoveryApprovalRequired
	}
	plan := value.Manifest.Plan
	endpoint, err := e.Probe(ctx)
	if err != nil {
		return err
	}
	if endpoint != plan.TargetEndpointIdentity || plan.InstallationId != e.installation {
		return ErrRecoveryApprovalRequired
	}
	labels := p.Config.Labels
	if labels[LabelPrefix+"installation"] != e.installation || labels[LabelPrefix+"tenant"] != plan.Challenge.TenantId || labels[LabelPrefix+"host"] != plan.Challenge.Identity.HostId || labels[LabelPrefix+"endpoint"] != plan.SourceEndpointIdentity {
		return ErrRecoveryApprovalRequired
	}
	for _, execution := range plan.Executions {
		if execution.ObservedResourceId == nil || *execution.ObservedResourceId != id || execution.CreationClaim != "verified" {
			continue
		}
		if labels[LabelPrefix+"execution"] != execution.ExecutionId || labels[LabelPrefix+"generation"] != execution.Generation || labels[LabelPrefix+"spec"] != execution.SpecHash {
			continue
		}
		for _, decision := range value.Manifest.Decisions {
			if decision.ExecutionId == execution.ExecutionId && decision.Generation == execution.Generation && (decision.Action == "cleanup" || decision.Action == "observe-and-cleanup") {
				if !a.Current(time.Now()) {
					return ErrRecoveryApprovalRequired
				}
				return e.check(ctx)
			}
		}
	}
	return ErrRecoveryApprovalRequired
}

// RecoverStop/RecoverRemove preserve immutable origin labels. They require a
// concrete approved Docker ID, repeat full configuration inspection, and recheck
// current scoped authority immediately before the one mutation. A 404 is merely
// an observation: callers still need complete inventory and durable cleanup facts.
func (e *Engine) RecoverStop(ctx context.Context, id string, p Plan, authority RecoveryAuthority) error {
	if !e.readOnly {
		return ErrRecoveryApprovalRequired
	}
	object, err := e.Inspect(ctx, id, p)
	if err != nil {
		return err
	}
	if object.ID != id {
		return ErrConflict
	}
	if err = e.recoveryCheck(ctx, id, p, authority); err != nil {
		return err
	}
	if object.State != "running" {
		return nil
	}
	seconds := 10
	if _, err = e.api.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: &seconds}); err != nil {
		return e.lost()
	}
	return nil
}
func (e *Engine) RecoverRemove(ctx context.Context, id string, p Plan, authority RecoveryAuthority) error {
	if !e.readOnly {
		return ErrRecoveryApprovalRequired
	}
	object, err := e.Inspect(ctx, id, p)
	if err != nil {
		return err
	}
	if object.ID != id || object.State == "running" {
		return ErrConflict
	}
	if err = e.recoveryCheck(ctx, id, p, authority); err != nil {
		return err
	}
	if _, err = e.api.ContainerRemove(ctx, id, client.ContainerRemoveOptions{}); err != nil {
		return e.lost()
	}
	return nil
}
