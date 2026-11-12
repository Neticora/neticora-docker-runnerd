//go:build linux

package execution

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/broker"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
)

// brokerRuntime carries identities, never Docker plans or privileged descriptors.
// The existing controller still owns its creation journal and start callback.
type brokerRuntime struct {
	controller *Controller
	remote     *HostRemote
	socket     string
	call       func(context.Context, string, broker.Request) (broker.Response, error)
	execute    func(context.Context, string, broker.ExecutionGrantRequest) error
}

var _ Runtime = (*brokerRuntime)(nil)

func brokerRuntimeFor(c *Controller, r *HostRemote, socket string) Runtime {
	b := &brokerRuntime{controller: c, remote: r, socket: socket, call: broker.Call}
	c.kataBroker = b
	return b
}

func (b *brokerRuntime) request(ctx context.Context, q broker.Request) (broker.Response, error) {
	q.Version = broker.Version
	r, err := b.call(ctx, b.socket, q)
	if err != nil {
		switch r.Code {
		case "resource_absent":
			return r, dockerengine.ErrAbsent
		case "storage_pressure":
			return r, dockerengine.ErrStoragePressure
		}
		return r, ErrReconcile
	}
	return r, nil
}

func (b *brokerRuntime) lookup(ctx context.Context, p dockerengine.Plan, id string) (broker.Lookup, error) {
	if p.Config == nil {
		return broker.Lookup{}, ErrReconcile
	}
	labels := p.Config.Labels
	q := broker.Lookup{ExecutionID: labels[dockerengine.LabelPrefix+"execution"], Generation: labels[dockerengine.LabelPrefix+"generation"], SpecHash: labels[dockerengine.LabelPrefix+"spec"], ResourceID: id}
	e, err := b.controller.Store.PeerRecoveryExecution(ctx, q.ExecutionID, q.Generation)
	if err != nil || e.Identity.InstallationID != b.controller.Scope.InstallationID || e.Identity.HostID != b.controller.Scope.HostID || e.Identity.TenantID != b.controller.Scope.TenantID || e.Identity.SpecHash != q.SpecHash {
		return q, ErrReconcile
	}
	start, err := b.controller.storedStart(e)
	if err != nil || (start.Spec.IsolationProfile != "standard" && (start.Spec.IsolationProfile != "isolated" || b.controller.Kata == nil || start.Spec.ProfileVersion != b.controller.Kata.ID)) {
		return q, ErrReconcile
	}
	return q, nil
}

func (b *brokerRuntime) state(ctx context.Context, q broker.Lookup) (broker.RuntimeState, error) {
	r, err := b.request(ctx, broker.Request{Operation: "ReconcileExecution", Lookup: &q})
	if r.Runtime == nil {
		return broker.RuntimeState{}, ErrReconcile
	}
	if err != nil && r.Code == "boot_recovery_required" {
		challenge, challengeErr := b.request(ctx, broker.Request{Operation: "GetBootRecoveryChallenge", Lookup: &q})
		if challengeErr != nil || challenge.BootChallenge == nil {
			return *r.Runtime, ErrReconcile
		}
		token, tokenErr := b.remote.credential(ctx)
		if tokenErr != nil {
			return *r.Runtime, tokenErr
		}
		certificate, certErr := b.remote.Client.BrokerBootRecovery(ctx, token, *challenge.BootChallenge)
		if certErr != nil {
			return *r.Runtime, certErr
		}
		if _, recoverErr := b.request(ctx, broker.Request{Operation: "RecoverBootExecution", BootCertificate: &certificate}); recoverErr != nil {
			return *r.Runtime, recoverErr
		}
		r, err = b.request(ctx, broker.Request{Operation: "ReconcileExecution", Lookup: &q})
		if r.Runtime == nil {
			return broker.RuntimeState{}, ErrReconcile
		}
	}
	if err != nil && r.Code == "reconciliation_required" && r.Runtime.Phase == "QUARANTINED" && (r.Runtime.Operations["RemoveExecution"].OperationID != "" || r.Runtime.Operations["DisposeUnstarted"].OperationID != "") {
		r, err = b.request(ctx, broker.Request{Operation: "ResumeDisposal", Lookup: &q})
		if r.Runtime == nil {
			return broker.RuntimeState{}, ErrReconcile
		}
	}
	return *r.Runtime, err
}

func (b *brokerRuntime) perform(ctx context.Context, action, id string, p dockerengine.Plan) (dockerengine.Object, error) {
	q, err := b.lookup(ctx, p, id)
	if err != nil {
		return dockerengine.Object{}, err
	}
	state, err := b.state(ctx, q)
	if err != nil && err != dockerengine.ErrAbsent {
		return dockerengine.Object{}, err
	}
	// Once an operation exists, observe its original effect. Never obtain another
	// grant using an advanced revision or create a replacement resource.
	if state.Phase == "RECOVERY_DISPOSED" {
		if action == "StopExecution" || action == "RemoveExecution" || action == "DisposeUnstarted" {
			return dockerengine.Object{ID: id, State: "removed"}, nil
		}
		return dockerengine.Object{}, ErrReconcile
	}
	if _, ok := state.Operations[action]; !ok {
		if action == "StartExecution" || action == "StopExecution" || action == "RemoveExecution" {
			if err = b.controller.flushExecutionEvents(ctx, q.ExecutionID, q.Generation); err != nil {
				return dockerengine.Object{}, err
			}
		}
		request := broker.ExecutionGrantRequest{Version: broker.ExecutionGrantVersion, Operation: action, ExecutionID: q.ExecutionID, Generation: q.Generation, ExpectedRevision: state.Revision, ResourceID: id}
		request.OperationID = request.OperationIdentity()
		execute := b.execute
		if execute == nil {
			execute = b.remote.executeBrokerOperation
		}
		if err = execute(ctx, b.socket, request); err != nil {
			// Lost replies are resolved through protected state, never by replaying
			// an expired grant or accepting a second authorization path.
			state, err = b.state(ctx, q)
			if err != nil && err != dockerengine.ErrAbsent {
				return dockerengine.Object{}, err
			}
		} else {
			state, err = b.state(ctx, q)
			if err != nil && err != dockerengine.ErrAbsent {
				return dockerengine.Object{}, err
			}
		}
	}
	if state.Operations[action].OperationID == "" {
		return dockerengine.Object{}, ErrReconcile
	}
	if action == "PrepareImage" {
		return dockerengine.Object{}, nil
	}
	if action == "RemoveExecution" && state.Phase == "REMOVED" {
		return dockerengine.Object{ID: id, State: "removed"}, nil
	}
	if action == "DisposeUnstarted" && state.Phase == "NEVER_CREATED" {
		return dockerengine.Object{}, nil
	}
	if action == "StopExecution" && (state.Phase == "STOPPED" || state.Phase == "REMOVED") && state.Object == nil {
		return dockerengine.Object{ID: id, State: "exited"}, nil
	}
	if state.Object == nil {
		return dockerengine.Object{}, ErrReconcile
	}
	if action == "StartExecution" && state.Object.State != "running" && state.Object.State != "exited" {
		return dockerengine.Object{}, ErrReconcile
	}
	if action == "StopExecution" && state.Object.State == "running" {
		return dockerengine.Object{}, ErrReconcile
	}
	return *state.Object, nil
}

func (b *brokerRuntime) Probe(ctx context.Context) (string, error) {
	r, err := b.request(ctx, broker.Request{Operation: "ProbeRuntime"})
	return r.Endpoint, err
}
func (b *brokerRuntime) Inventory(ctx context.Context) ([]string, error) {
	r, err := b.request(ctx, broker.Request{Operation: "GetRuntimeInventory"})
	return r.Inventory, err
}
func (b *brokerRuntime) Inspect(ctx context.Context, id string, p dockerengine.Plan) (dockerengine.Object, error) {
	// Names are local hints only; lookup carries no arbitrary Docker reference.
	resource := id
	if id == p.Name {
		resource = ""
	}
	q, err := b.lookup(ctx, p, resource)
	if err != nil {
		return dockerengine.Object{}, err
	}
	state, err := b.state(ctx, q)
	if err != nil {
		return dockerengine.Object{}, err
	}
	if state.Object == nil {
		return dockerengine.Object{}, dockerengine.ErrAbsent
	}
	return *state.Object, nil
}
func (b *brokerRuntime) PrepareImage(ctx context.Context, p dockerengine.Plan) error {
	_, err := b.perform(ctx, "PrepareImage", "", p)
	return err
}
func (b *brokerRuntime) Ensure(ctx context.Context, p dockerengine.Plan, claim func() error) (dockerengine.Object, error) {
	if claim == nil {
		return dockerengine.Object{}, ErrReconcile
	}
	q, err := b.lookup(ctx, p, "")
	if err != nil {
		return dockerengine.Object{}, err
	}
	state, err := b.state(ctx, q)
	if err != nil && err != dockerengine.ErrAbsent {
		return dockerengine.Object{}, err
	}
	if state.Operations["CreateExecution"].OperationID != "" {
		if state.Object == nil {
			return dockerengine.Object{}, ErrReconcile
		}
		e, err := b.controller.Store.PeerRecoveryExecution(ctx, q.ExecutionID, q.Generation)
		if err != nil {
			return dockerengine.Object{}, err
		}
		if err = b.controller.Store.VerifyCreationClaim(ctx, b.controller.Scope, e.Command); err != nil {
			return dockerengine.Object{}, err
		}
		// Match Engine.Ensure: an original already-created object must not run
		// the one-time creation callback again. Start still performs its fresh
		// authorization callback and independently committed broker operation.
		return *state.Object, nil
	}
	if err := claim(); err != nil {
		return dockerengine.Object{}, err
	}
	return b.perform(ctx, "CreateExecution", "", p)
}
func (b *brokerRuntime) Start(ctx context.Context, id string, p dockerengine.Plan, authorize func() error) (dockerengine.Object, error) {
	if authorize == nil {
		return dockerengine.Object{}, ErrReconcile
	}
	if err := authorize(); err != nil {
		return dockerengine.Object{}, err
	}
	return b.perform(ctx, "StartExecution", id, p)
}
func (b *brokerRuntime) Stop(ctx context.Context, id string, p dockerengine.Plan) error {
	_, err := b.perform(ctx, "StopExecution", id, p)
	return err
}
func (b *brokerRuntime) Remove(ctx context.Context, id string, p dockerengine.Plan) error {
	_, err := b.perform(ctx, "RemoveExecution", id, p)
	return err
}
func (b *brokerRuntime) CheckHeadroom(ctx context.Context, n uint64) error {
	_, err := b.request(ctx, broker.Request{Operation: "CheckRuntimeHeadroom", MinimumFreeBytes: n})
	return err
}
func (b *brokerRuntime) Watch(ctx context.Context, wake func()) error {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			wake()
		}
	}
}
func (b *brokerRuntime) Registration(ctx context.Context, p dockerengine.Plan) (json.RawMessage, error) {
	q, err := b.lookup(ctx, p, "")
	if err != nil {
		return nil, err
	}
	r, err := b.request(ctx, broker.Request{Operation: "ReadRegistration", Lookup: &q})
	return r.Registration, err
}

func (b *brokerRuntime) VerifyDisposal(ctx context.Context, id string, p dockerengine.Plan) error {
	q, err := b.lookup(ctx, p, id)
	if err != nil {
		return err
	}
	state, stateErr := b.state(ctx, q)
	if stateErr != nil && stateErr != dockerengine.ErrAbsent {
		return stateErr
	}
	q.RecoveryID = state.RecoveryID
	token, err := b.remote.credential(ctx)
	if err != nil {
		return err
	}
	challenge, err := b.remote.Client.BrokerDisposalChallenge(ctx, token, q)
	if err != nil {
		return err
	}
	r, err := b.request(ctx, broker.Request{Operation: "AttestDisposal", DisposalChallenge: &challenge})
	if err != nil || r.Disposal == nil || r.Code != "disposal_observed" {
		return ErrReconcile
	}
	return b.remote.Client.BrokerDisposal(ctx, token, *r.Disposal)
}

func (b *brokerRuntime) DisposeUnstarted(ctx context.Context, p dockerengine.Plan) error {
	if _, err := b.perform(ctx, "DisposeUnstarted", "", p); err != nil {
		return err
	}
	return b.VerifyDisposal(ctx, "", p)
}

func (b *brokerRuntime) KataHealthy(ctx context.Context, id string, p dockerengine.Plan) bool {
	q, err := b.lookup(ctx, p, id)
	if err != nil {
		return false
	}
	state, err := b.state(ctx, q)
	return err == nil && state.KataHealthy != nil && *state.KataHealthy
}
func (b *brokerRuntime) VerifyKataAbsence(ctx context.Context, id string, p dockerengine.Plan) error {
	q, err := b.lookup(ctx, p, id)
	if err != nil {
		return err
	}
	state, err := b.state(ctx, q)
	if err == dockerengine.ErrAbsent && (state.Phase == "REMOVED" || (state.Phase == "RECOVERY_DISPOSED" && state.RecoveryID != "")) && state.Object == nil {
		return nil
	}
	return ErrReconcile
}
func (b *brokerRuntime) KataPhysicalEvidence(ctx context.Context, id string, p dockerengine.Plan) (katalinux.Evidence, error) {
	var evidence katalinux.Evidence
	q, err := b.lookup(ctx, p, id)
	if err != nil {
		return evidence, err
	}
	response, err := b.request(ctx, broker.Request{Operation: "ReadKataEvidence", Lookup: &q})
	if err != nil || len(response.KataEvidence) == 0 {
		return evidence, ErrReconcile
	}
	if json.Unmarshal(response.KataEvidence, &evidence) != nil || evidence.Container != id || evidence.Profile != b.controller.Kata.ID {
		return evidence, ErrReconcile
	}
	return evidence, nil
}
