package execution

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

type PeerRecoveryRemote interface {
	Recovery(context.Context, []agent.ExecutionCursor) (protocol.RecoveryState, error)
	PeerRecovery(context.Context, string, bool) ([]byte, error)
	Inventory(context.Context, protocol.Outbound) error
	Events(context.Context, protocol.Outbound) ([]protocol.EventAck, error)
	Commands(context.Context) ([]json.RawMessage, error)
	Ack(context.Context, agent.Receipt) error
}

// RecoveryRuntime intentionally has no prepare/create/start operation.
type RecoveryRuntime interface {
	Probe(context.Context) (string, error)
	Inventory(context.Context) ([]string, error)
	Inspect(context.Context, string, dockerengine.Plan) (dockerengine.Object, error)
	RecoverStop(context.Context, string, dockerengine.Plan, dockerengine.RecoveryAuthority) error
	RecoverRemove(context.Context, string, dockerengine.Plan, dockerengine.RecoveryAuthority) error
}

type PeerRecoveryCoordinator struct {
	Store                                          *journal.SQLiteStore
	Runtime                                        RecoveryRuntime // Production wiring uses OpenReadOnly.
	Remote                                         PeerRecoveryRemote
	Profile                                        standardlinux.Settings
	PublicKey                                      []byte // Independent operator public key, never a signer.
	Identity                                       protocol.HostIdentity
	TenantID, InstallationID, BootID, AgentVersion string
}

func (c *PeerRecoveryCoordinator) executions(ctx context.Context) ([]agent.Execution, error) {
	out := []agent.Execution{}
	cursor := agent.ExecutionCursor{}
	for {
		page, err := c.Store.Incomplete(ctx, cursor, 100)
		if err != nil {
			return nil, err
		}
		if len(out)+len(page) > 1000 {
			return nil, ErrReconcile
		}
		out = append(out, page...)
		if len(page) < 100 {
			return out, nil
		}
		last := page[len(page)-1]
		cursor = agent.ExecutionCursor{ExecutionID: last.Identity.ExecutionID, Generation: last.Identity.Generation}
	}
}

func (c *PeerRecoveryCoordinator) originPlan(e agent.Execution, source string) (dockerengine.Plan, error) {
	start, err := protocol.DecodeStartCommand(e.Command)
	if err != nil || protocol.ValidateInboundJSON("StartCommand", e.Command) != nil || start.CommandId != e.CommandID || start.Spec.ExecutionId != e.Identity.ExecutionID || start.Spec.SpecHash != e.Identity.SpecHash || start.Spec.Generation != e.Identity.Generation || start.Spec.AttemptId != e.Identity.AttemptID || e.Identity.InstallationID != c.InstallationID || e.Identity.TenantID != c.TenantID || e.Identity.HostID != c.Identity.HostId {
		return dockerengine.Plan{}, ErrReconcile
	}
	return c.Profile.Plan(agent.StoreScope{InstallationID: c.InstallationID, TenantID: c.TenantID, HostID: c.Identity.HostId, EndpointIdentity: source, SessionEpoch: c.Identity.SessionEpoch}, start.Spec)
}

// Propose collects read-only evidence against an already fenced, authenticated
// operator challenge. It does not accept new commands or mutate Docker.
func (c *PeerRecoveryCoordinator) Propose(ctx context.Context, challenge protocol.PeerRecoveryChallenge, key ed25519.PrivateKey) (protocol.SignedPeerRecoveryPlan, error) {
	if len(key) != ed25519.PrivateKeySize || challenge.Identity != c.Identity || challenge.TenantId != c.TenantID {
		return protocol.SignedPeerRecoveryPlan{}, ErrReconcile
	}
	scope, err := c.Store.PeerRecoveryScope(ctx)
	if err != nil {
		return protocol.SignedPeerRecoveryPlan{}, err
	}
	if scope.InstallationID != c.InstallationID || scope.HostID != c.Identity.HostId || scope.TenantID != c.TenantID {
		return protocol.SignedPeerRecoveryPlan{}, ErrReconcile
	}
	endpoint, err := c.Runtime.Probe(ctx)
	if err != nil {
		return protocol.SignedPeerRecoveryPlan{}, ErrReconcile
	}
	rows, err := c.executions(ctx)
	if err != nil {
		return protocol.SignedPeerRecoveryPlan{}, err
	}
	if endpoint == scope.EndpointIdentity {
		// An idle native journal may already have applied the peer without
		// finalizing its grant. Renewal on that same peer retains the recorded
		// transition; an actually newer peer starts from native committed scope.
		prior, err := c.Store.CurrentPeerRecovery(ctx)
		if err != nil || len(rows) != 0 || prior.Manifest.Plan.TargetEndpointIdentity != endpoint || prior.Manifest.Plan.SourceEndpointIdentity == endpoint {
			return protocol.SignedPeerRecoveryPlan{}, ErrReconcile
		}
		scope.EndpointIdentity = prior.Manifest.Plan.SourceEndpointIdentity
	}
	lookups := make([]agent.ExecutionCursor, 0, len(rows))
	for _, e := range rows {
		lookups = append(lookups, agent.ExecutionCursor{ExecutionID: e.Identity.ExecutionID, Generation: e.Identity.Generation})
	}
	authority, err := c.Remote.Recovery(ctx, lookups)
	if err != nil || authority.Identity != c.Identity {
		return protocol.SignedPeerRecoveryPlan{}, ErrReconcile
	}
	inventory, err := c.Runtime.Inventory(ctx)
	if err != nil {
		return protocol.SignedPeerRecoveryPlan{}, err
	}
	sort.Strings(inventory)
	entries := make([]protocol.PeerRecoveryExecutionPlan, 0, len(rows))
	known := map[string]bool{}
	h := c.Store.Health(ctx)
	for _, e := range rows {
		p, err := c.originPlan(e, scope.EndpointIdentity)
		if err != nil {
			return protocol.SignedPeerRecoveryPlan{}, err
		}
		start, err := protocol.DecodeStartCommand(e.Command)
		if err != nil {
			return protocol.SignedPeerRecoveryPlan{}, err
		}
		var original *protocol.RuntimeRef
		id := p.Name
		if len(e.RuntimeRef) > 0 {
			ref, err := protocol.DecodeRuntimeRef(e.RuntimeRef)
			if err != nil {
				return protocol.SignedPeerRecoveryPlan{}, err
			}
			original = &ref
			id = ref.ResourceId
		}
		o, inspectErr := c.Runtime.Inspect(ctx, id, p)
		observed := protocol.PeerRecoveryExecutionPlanObservedState(o.State)
		var resource *string
		switch {
		case errors.Is(inspectErr, dockerengine.ErrAbsent):
			observed = "absent"
		case inspectErr != nil:
			observed = "unknown"
		default:
			resource = &o.ID
			known[o.ID] = true
		}
		inspectionHash, err := peerrecovery.Hash(o)
		if err != nil {
			return protocol.SignedPeerRecoveryPlan{}, err
		}
		claim := protocol.PeerRecoveryExecutionPlanCreationClaim("ambiguous")
		if c.Store.VerifyCreationClaim(ctx, scope, e.Command) == nil {
			claim = "verified"
		}
		pending := []protocol.PeerRecoveryEventReference{}
		after := e.AckSequence
		for {
			events, err := c.Store.PeerRecoveryPending(ctx, e.Identity.ExecutionID, e.Identity.Generation, after, 100)
			if err != nil {
				return protocol.SignedPeerRecoveryPlan{}, err
			}
			for _, raw := range events {
				var fact eventDocumentForRecovery
				if protocol.ValidateInboundJSON("HostEvent", raw) != nil || json.Unmarshal(raw, &fact) != nil {
					return protocol.SignedPeerRecoveryPlan{}, ErrReconcile
				}
				pending = append(pending, protocol.PeerRecoveryEventReference{EventId: fact.EventID, Sequence: fact.Sequence, PayloadHash: fact.PayloadHash})
				after = fact.Sequence
			}
			if len(events) < 100 {
				break
			}
			if len(pending) > 1000 {
				return protocol.SignedPeerRecoveryPlan{}, ErrReconcile
			}
		}
		origin, err := c.Store.PeerRecoveryExecutionScope(ctx, e.Identity.ExecutionID, e.Identity.Generation)
		if err != nil {
			return protocol.SignedPeerRecoveryPlan{}, err
		}
		if origin.EndpointIdentity != scope.EndpointIdentity {
			return protocol.SignedPeerRecoveryPlan{}, ErrReconcile
		}
		epoch := origin.SessionEpoch
		serverFound := false
		for _, entry := range authority.Entries {
			if entry.ExecutionId == e.Identity.ExecutionID && entry.Generation == e.Identity.Generation {
				serverFound = true
				if entry.CommandId != e.CommandID || entry.SpecHash != e.Identity.SpecHash {
					return protocol.SignedPeerRecoveryPlan{}, ErrReconcile
				}
			}
		}
		if !serverFound {
			return protocol.SignedPeerRecoveryPlan{}, ErrReconcile
		}
		entries = append(entries, protocol.PeerRecoveryExecutionPlan{ExecutionId: e.Identity.ExecutionID, Generation: e.Identity.Generation, OriginalSessionEpoch: epoch, SpecHash: e.Identity.SpecHash, StartCommandHash: start.PayloadHash, OriginalRuntimeRef: original, ObservedResourceId: resource, ObservedState: observed, InspectionHash: inspectionHash, LastSequence: e.LastSequence, AckSequence: e.AckSequence, PendingEvents: pending, CreationClaim: claim, NativeState: e.State})
	}
	for _, id := range inventory {
		if !known[id] {
			return protocol.SignedPeerRecoveryPlan{}, ErrReconcile
		}
	}
	after, err := c.Runtime.Probe(ctx)
	if err != nil || after != endpoint {
		return protocol.SignedPeerRecoveryPlan{}, ErrReconcile
	}
	if current := c.Store.Health(ctx); current.JournalID != h.JournalID || current.Revision != h.Revision {
		return protocol.SignedPeerRecoveryPlan{}, ErrReconcile
	}
	generation, err := strconv.ParseUint(authority.InventoryGeneration, 10, 64)
	if err != nil || generation == ^uint64(0) {
		return protocol.SignedPeerRecoveryPlan{}, ErrReconcile
	}
	inventoryHash, _ := peerrecovery.Hash(inventory)
	plan := protocol.PeerRecoveryPlan{Domain: "neticora-runnerd-peer-recovery-plan-v1", Challenge: challenge, InstallationId: c.InstallationID, BootId: c.BootID, AgentVersion: c.AgentVersion, SourceEndpointIdentity: scope.EndpointIdentity, TargetEndpointIdentity: endpoint, JournalId: h.JournalID, JournalRevision: h.Revision, InventoryGeneration: strconv.FormatUint(generation+1, 10), InventoryHash: inventoryHash, ObservedAt: time.Now().UTC().Format(wireTime), Executions: entries}
	if peerrecovery.ValidatePlan(plan) != nil {
		return protocol.SignedPeerRecoveryPlan{}, ErrReconcile
	}
	raw, err := peerrecovery.Canonical(plan)
	if err != nil {
		return protocol.SignedPeerRecoveryPlan{}, err
	}
	return protocol.SignedPeerRecoveryPlan{Plan: plan, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))}, nil
}

type eventDocumentForRecovery struct {
	EventID     string `json:"eventId"`
	Sequence    string `json:"sequence"`
	PayloadHash string `json:"payloadHash"`
}

func (c *PeerRecoveryCoordinator) scope(plan protocol.PeerRecoveryPlan) agent.StoreScope {
	return agent.StoreScope{InstallationID: c.InstallationID, TenantID: c.TenantID, HostID: c.Identity.HostId, SessionEpoch: c.Identity.SessionEpoch, EndpointIdentity: plan.TargetEndpointIdentity}
}
func (c *PeerRecoveryCoordinator) authorization(ctx context.Context, approved protocol.SignedPeerRecoveryApproval) (*peerrecovery.Authorization, error) {
	progress, err := c.Store.PeerRecoveryProgress(ctx, approved.Manifest.Plan)
	if err != nil {
		return nil, err
	}
	raw, err := c.Remote.PeerRecovery(ctx, approved.Manifest.ApprovalId, false)
	if err != nil {
		return nil, err
	}
	return peerrecovery.VerifyContinuing(raw, c.PublicKey, approved.Manifest.Plan, progress, time.Now())
}
func (c *PeerRecoveryCoordinator) flush(ctx context.Context, plan protocol.PeerRecoveryPlan) error {
	for _, e := range plan.Executions {
		native, err := c.Store.PeerRecoveryExecution(ctx, e.ExecutionId, e.Generation)
		if err != nil {
			return err
		}
		for {
			events, err := c.Store.PendingEvents(ctx, agent.EventPage{ExecutionID: e.ExecutionId, Generation: e.Generation, AfterSequence: native.AckSequence, Limit: 100})
			if err != nil {
				return err
			}
			if len(events) == 0 {
				break
			}
			message, err := protocol.EncodeValidated("EventBatch", map[string]any{"events": events})
			if err != nil {
				return err
			}
			acks, err := c.Remote.Events(ctx, message)
			if err != nil {
				return err
			}
			advanced := false
			for _, ack := range acks {
				if ack.ExecutionId != e.ExecutionId || ack.Generation != e.Generation {
					return ErrReconcile
				}
				if err = c.Store.AckEvents(ctx, c.scope(plan), agent.Watermark{ExecutionID: ack.ExecutionId, Generation: ack.Generation, ContiguousSequence: ack.ContiguousSequence}); err != nil {
					return err
				}
				if paddedCounter(ack.ContiguousSequence) > paddedCounter(native.AckSequence) {
					native.AckSequence = ack.ContiguousSequence
					advanced = true
				}
			}
			if !advanced {
				return ErrReconcile
			}
		}
	}
	return nil
}
func paddedCounter(s string) string { return strings.Repeat("0", 20-len(s)) + s }

func (c *PeerRecoveryCoordinator) controls(ctx context.Context, plan protocol.PeerRecoveryPlan, e agent.Execution) error {
	commands, err := c.Remote.Commands(ctx)
	if err != nil {
		return err
	}
	for _, raw := range commands {
		var command struct {
			ExecutionID string `json:"executionId"`
			Generation  string `json:"generation"`
			Kind        string `json:"kind"`
		}
		if json.Unmarshal(raw, &command) != nil {
			return ErrReconcile
		}
		if command.ExecutionID != e.Identity.ExecutionID || command.Generation != e.Identity.Generation || (command.Kind != "cancel" && command.Kind != "cleanup") {
			continue
		}
		receipt, err := c.Store.AcceptCommand(ctx, c.scope(plan), raw)
		if err != nil {
			return err
		}
		if err = c.Remote.Ack(ctx, receipt); err != nil {
			return err
		}
	}
	controls, err := c.Store.ControlCommands(ctx, e.Identity.ExecutionID, e.Identity.Generation)
	if err != nil {
		return err
	}
	for _, raw := range controls {
		var control struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(raw, &control) != nil {
			return ErrReconcile
		}
		if control.Kind == "cleanup" {
			return nil
		}
	}
	return ErrReconcile
}

func (c *PeerRecoveryCoordinator) inventory(ctx context.Context, plan protocol.PeerRecoveryPlan) (string, time.Time, error) {
	ids, err := c.Runtime.Inventory(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	observations := []any{}
	known := map[string]bool{}
	origin := &Controller{Scope: c.scope(plan)}
	origin.Scope.EndpointIdentity = plan.SourceEndpointIdentity
	for _, entry := range plan.Executions {
		e, err := c.Store.PeerRecoveryExecution(ctx, entry.ExecutionId, entry.Generation)
		if err != nil {
			return "", time.Time{}, err
		}
		p, err := c.originPlan(e, plan.SourceEndpointIdentity)
		if err != nil {
			return "", time.Time{}, err
		}
		id := p.Name
		if entry.ObservedResourceId != nil {
			id = *entry.ObservedResourceId
		} else if entry.OriginalRuntimeRef != nil {
			id = entry.OriginalRuntimeRef.ResourceId
		}
		object, err := c.Runtime.Inspect(ctx, id, p)
		if errors.Is(err, dockerengine.ErrAbsent) {
			continue
		}
		if err != nil || e.State == "cleaned" {
			return "", time.Time{}, ErrReconcile
		}
		known[object.ID] = true
		observations = append(observations, origin.observation(e, object))
	}
	for _, id := range ids {
		if !known[id] {
			return "", time.Time{}, ErrReconcile
		}
	}
	lookups := []agent.ExecutionCursor{}
	for _, e := range plan.Executions {
		lookups = append(lookups, agent.ExecutionCursor{ExecutionID: e.ExecutionId, Generation: e.Generation})
	}
	state, err := c.Remote.Recovery(ctx, lookups)
	if err != nil || state.Identity != c.Identity || state.EndpointIdentity != plan.TargetEndpointIdentity {
		return "", time.Time{}, ErrReconcile
	}
	n, err := strconv.ParseUint(state.InventoryGeneration, 10, 64)
	if err != nil || n == ^uint64(0) {
		return "", time.Time{}, ErrReconcile
	}
	generation := strconv.FormatUint(n+1, 10)
	observed := time.Now().UTC().Truncate(time.Millisecond)
	snapshot, err := protocol.EncodeValidated("InventorySnapshot", map[string]any{"inventoryGeneration": generation, "endpointIdentity": plan.TargetEndpointIdentity, "complete": true, "observedAt": observed.Format(wireTime), "resources": observations})
	if err != nil {
		return "", time.Time{}, err
	}
	if err = c.Remote.Inventory(ctx, snapshot); err != nil {
		return "", time.Time{}, err
	}
	state, err = c.Remote.Recovery(ctx, lookups)
	if err != nil || state.Identity != c.Identity || state.InventoryGeneration != generation || state.EndpointIdentity != plan.TargetEndpointIdentity {
		return "", time.Time{}, ErrReconcile
	}
	watermarks := make([]agent.Watermark, 0, len(state.Entries))
	for _, entry := range state.Entries {
		watermarks = append(watermarks, agent.Watermark{ExecutionID: entry.ExecutionId, Generation: entry.Generation, ContiguousSequence: entry.ContiguousSequence})
	}
	health := c.Store.Health(ctx)
	if err = c.Store.Reconcile(ctx, agent.RecoveryCheckpoint{JournalID: health.JournalID, Revision: health.Revision, Scope: c.scope(plan), InventoryGeneration: generation, ObservedAt: observed, ServerWatermarks: watermarks}); err != nil {
		return "", time.Time{}, err
	}
	return generation, observed, nil
}

// Apply never starts a container or reports execution success. It resumes only
// approved cleanup and durable event replay; any ambiguity retains its hold.
func (c *PeerRecoveryCoordinator) Apply(ctx context.Context, approved protocol.SignedPeerRecoveryApproval) error {
	plan := approved.Manifest.Plan
	if plan.InstallationId != c.InstallationID || plan.Challenge.TenantId != c.TenantID || plan.Challenge.Identity != c.Identity || plan.BootId != c.BootID || plan.AgentVersion != c.AgentVersion {
		return ErrReconcile
	}
	raw, err := peerrecovery.Canonical(approved)
	if err != nil {
		return err
	}
	checked, err := peerrecovery.VerifyRecordedApproval(raw, c.PublicKey, plan, time.Now())
	if err != nil {
		return err
	}
	endpoint, err := c.Runtime.Probe(ctx)
	if err != nil || endpoint != plan.TargetEndpointIdentity {
		return ErrReconcile
	}
	completed, err := c.Store.CompletedPeerRecovery(ctx, checked)
	if err != nil {
		return err
	}
	if completed {
		return c.finalize(ctx, approved, checked, true)
	}
	ready, err := c.Store.PeerRecoveryCompletionReady(ctx, checked)
	if err != nil {
		return err
	}
	if ready {
		// A durable completion intent (or fully ACKed legacy cleanup) must not
		// request ordinary authorization after the platform reached COMPLETED.
		return c.finalize(ctx, approved, checked, false)
	}
	// Historical signature verification above is never mutation permission.
	if _, err = peerrecovery.VerifyApproval(raw, c.PublicKey, plan, time.Now()); err != nil {
		return err
	}
	prior, priorErr := c.Store.CurrentPeerRecovery(ctx)
	sameApproval := false
	if priorErr == nil {
		hash, _ := peerrecovery.Hash(prior)
		sameApproval = hash == checked.Hash()
	} else if !errors.Is(priorErr, agent.ErrNotFound) {
		return priorErr
	}
	if errors.Is(priorErr, agent.ErrNotFound) || !sameApproval {
		ids, err := c.Runtime.Inventory(ctx)
		if err != nil {
			return err
		}
		sort.Strings(ids)
		digest, _ := peerrecovery.Hash(ids)
		if digest != plan.InventoryHash {
			return ErrReconcile
		}
		for _, entry := range plan.Executions {
			e, err := c.Store.PeerRecoveryExecution(ctx, entry.ExecutionId, entry.Generation)
			if err != nil {
				return err
			}
			p, err := c.originPlan(e, plan.SourceEndpointIdentity)
			if err != nil {
				return err
			}
			id := p.Name
			if entry.ObservedResourceId != nil {
				id = *entry.ObservedResourceId
			} else if entry.OriginalRuntimeRef != nil {
				id = entry.OriginalRuntimeRef.ResourceId
			}
			object, inspectErr := c.Runtime.Inspect(ctx, id, p)
			if entry.ObservedState == "absent" {
				if !errors.Is(inspectErr, dockerengine.ErrAbsent) {
					return ErrReconcile
				}
			} else if entry.ObservedState != "unknown" {
				digest, _ := peerrecovery.Hash(object)
				if inspectErr != nil || digest != entry.InspectionHash {
					return ErrReconcile
				}
			}
		}
	}
	authority, err := c.authorization(ctx, approved)
	if err != nil {
		return err
	}
	if err = c.Store.ApplyPeerRecovery(ctx, authority); err != nil {
		return fmt.Errorf("apply approved journal transition: %w", err)
	}
	if err = c.flush(ctx, plan); err != nil {
		return err
	}
	held := false
	origin := &Controller{Scope: c.scope(plan), Profile: c.Profile}
	origin.Scope.EndpointIdentity = plan.SourceEndpointIdentity
	for _, decision := range approved.Manifest.Decisions {
		if decision.Action == "hold" {
			held = true
			continue
		}
		e, err := c.Store.PeerRecoveryExecution(ctx, decision.ExecutionId, decision.Generation)
		if err != nil {
			return err
		}
		if e.State == "cleaned" {
			continue
		}
		p, err := c.originPlan(e, plan.SourceEndpointIdentity)
		if err != nil {
			return err
		}
		var entry *protocol.PeerRecoveryExecutionPlan
		for _, item := range plan.Executions {
			if item.ExecutionId == decision.ExecutionId && item.Generation == decision.Generation {
				entry = &item
				break
			}
		}
		if entry == nil {
			return ErrReconcile
		}
		id := ""
		if entry.ObservedResourceId != nil {
			id = *entry.ObservedResourceId
		} else if entry.OriginalRuntimeRef != nil {
			id = entry.OriginalRuntimeRef.ResourceId
		}
		if id == "" {
			return ErrReconcile
		}
		object, inspectErr := c.Runtime.Inspect(ctx, id, p)
		if inspectErr != nil && !errors.Is(inspectErr, dockerengine.ErrAbsent) {
			return inspectErr
		}
		object.ID = id
		if !e.CleanupPending {
			object.State = "cleanup-pending"
			event, err := origin.event(e, origin.observation(e, object), nil)
			if err != nil {
				return err
			}
			if err = c.Store.RequireCleanup(ctx, c.scope(plan), event); err != nil {
				return fmt.Errorf("commit recovery cleanup obligation: %w", err)
			}
			if err = c.flush(ctx, plan); err != nil {
				return err
			}
			e, err = c.Store.PeerRecoveryExecution(ctx, decision.ExecutionId, decision.Generation)
			if err != nil {
				return err
			}
		}
		if err = c.controls(ctx, plan, e); err != nil {
			return fmt.Errorf("acknowledge recovery cleanup command: %w", err)
		}
		authorize := func(ctx context.Context) (*peerrecovery.Authorization, error) {
			a, err := c.authorization(ctx, approved)
			if err != nil {
				return nil, err
			}
			if err = c.Store.CheckPeerRecoveryMutation(ctx, a, decision.ExecutionId, decision.Generation); err != nil {
				return nil, err
			}
			return a, nil
		}
		if inspectErr == nil {
			if err = c.Runtime.RecoverStop(ctx, id, p, authorize); err != nil {
				return err
			}
			if err = c.Runtime.RecoverRemove(ctx, id, p, authorize); err != nil {
				return err
			}
		} else if entry.ObservedState == "absent" && decision.Action != "verify-absent" {
			return ErrReconcile
		}
		if _, err = c.Runtime.Inspect(ctx, id, p); !errors.Is(err, dockerengine.ErrAbsent) {
			return ErrReconcile
		}
		if _, err = authorize(ctx); err != nil {
			return err
		}
		generation, observed, err := c.inventory(ctx, plan)
		if err != nil {
			return err
		}
		e, err = c.Store.PeerRecoveryExecution(ctx, decision.ExecutionId, decision.Generation)
		if err != nil {
			return err
		}
		object.State = "cleaned"
		observation := origin.observation(e, object)
		observation["observedAt"] = observed.Format(wireTime)
		event, err := origin.event(e, observation, nil)
		if err != nil {
			return err
		}
		ref, _ := json.Marshal(observation["runtimeRef"])
		if err = c.Store.CompleteCleanup(ctx, c.scope(plan), event, agent.AbsenceEvidence{RuntimeRef: ref, EndpointIdentity: plan.TargetEndpointIdentity, InventoryGeneration: generation, ObservedAt: observed}); err != nil {
			return fmt.Errorf("commit verified recovery absence: %w", err)
		}
		origin.cleanSecrets(e, p)
		if err = c.flush(ctx, plan); err != nil {
			return err
		}
	}
	if held {
		return ErrReconcile
	}
	if err = c.flush(ctx, plan); err != nil {
		return err
	}
	return c.finalize(ctx, approved, checked, false)
}

// finalize has no mutation/command/event path. A fresh inventory and exact ACKed
// suffix are required on every retry, including after signed approval expiry.
func (c *PeerRecoveryCoordinator) finalize(ctx context.Context, approved protocol.SignedPeerRecoveryApproval, checked *peerrecovery.OperatorApproval, completed bool) error {
	plan := approved.Manifest.Plan
	finalGeneration, finalObserved, err := c.inventory(ctx, plan)
	if err != nil {
		return err
	}
	ids, err := c.Runtime.Inventory(ctx)
	if err != nil || len(ids) != 0 {
		return ErrReconcile
	}
	progress, err := c.Store.PeerRecoveryProgress(ctx, plan)
	if err != nil {
		return err
	}
	for _, e := range progress {
		if e.LastSequence != e.AckSequence {
			return ErrReconcile
		}
	}
	if !completed {
		h := c.Store.Health(ctx)
		if err = c.Store.BeginPeerRecoveryCompletion(ctx, checked, agent.RecoveryCheckpoint{JournalID: h.JournalID, Revision: h.Revision, Scope: c.scope(plan), InventoryGeneration: finalGeneration, ObservedAt: finalObserved}); err != nil {
			return err
		}
	}
	reply, err := c.Remote.PeerRecovery(ctx, approved.Manifest.ApprovalId, true)
	if err != nil {
		return err
	}
	completion, err := peerrecovery.VerifyCompletion(reply, c.PublicKey, plan, progress, time.Now())
	if err != nil {
		return err
	}
	if completion.ApprovalHash() != checked.Hash() {
		return ErrReconcile
	}
	endpoint, err := c.Runtime.Probe(ctx)
	if err != nil || endpoint != plan.TargetEndpointIdentity {
		return ErrReconcile
	}
	if completed {
		return nil
	}
	h := c.Store.Health(ctx)
	return c.Store.CompletePeerRecovery(ctx, completion, agent.RecoveryCheckpoint{JournalID: h.JournalID, Revision: h.Revision, Scope: c.scope(plan), InventoryGeneration: finalGeneration, ObservedAt: finalObserved})
}
