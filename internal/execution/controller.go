// Package execution connects durable recovery, authorization and a runtime.
package execution

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	"github.com/Neticora/neticora-docker-runnerd/journal"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

var ErrReconcile = errors.New("execution requires authoritative reconciliation")
var ErrBootstrap = errors.New("bootstrap envelope rejected")

const wireTime = "2006-01-02T15:04:05.000Z"

// Runtime permits deterministic fault injection without granting a fake runtime
// authority in the daemon. Production construction always supplies Docker Engine.
type Runtime interface {
	Probe(context.Context) (string, error)
	Inventory(context.Context) ([]string, error)
	Inspect(context.Context, string, dockerengine.Plan) (dockerengine.Object, error)
	PrepareImage(context.Context, dockerengine.Plan) error
	Ensure(context.Context, dockerengine.Plan, func() error) (dockerengine.Object, error)
	Start(context.Context, string, dockerengine.Plan, func() error) (dockerengine.Object, error)
	Stop(context.Context, string, dockerengine.Plan) error
	Remove(context.Context, string, dockerengine.Plan) error
	Watch(context.Context, func()) error
	CheckHeadroom(context.Context, uint64) error
}
type Remote interface {
	Recovery(context.Context, []agent.ExecutionCursor) (protocol.RecoveryState, error)
	Commands(context.Context) ([]json.RawMessage, error)
	Ack(context.Context, agent.Receipt) error
	Inventory(context.Context, protocol.Outbound) error
	Events(context.Context, protocol.Outbound) ([]protocol.EventAck, error)
	Start(context.Context, protocol.Outbound) (protocol.StartResponse, error)
	Admission(context.Context, protocol.ExecutionSpec) error
	Heartbeat(context.Context, string) error
}

type Controller struct {
	Kata                *katalinux.Profile
	Store               *journal.SQLiteStore
	Runtime             Runtime
	Remote              Remote
	Scope               agent.StoreScope
	Authority           journal.Authority
	SigningKey          ed25519.PrivateKey
	Profile             standardlinux.Settings
	Policy              func() *standardlinux.Policy
	VerifyImage         func(context.Context, *standardlinux.Policy, string, string, time.Time) error
	KeysDirectory       string
	Organization        string
	Repository          string
	Pool                string
	Drained             func() bool
	HostLimits          agent.ReservationLimits
	MinRuntimeFreeBytes uint64
	mu                  sync.Mutex // One reconciliation owner; all work remains durable in Store.
	launchMu            sync.Mutex // Serializes durable command acceptance with final Docker start.
	wake                chan struct{}
	cancelled           map[agent.ExecutionCursor]bool
	inventoryGeneration string
	inventoryObservedAt time.Time
	heartbeatGeneration atomic.Value
	status              atomic.Value
}

func (c *Controller) Status() string {
	v := c.status.Load()
	if v == nil {
		return "starting"
	}
	return v.(string)
}
func failureReason(err error) string {
	switch {
	case errors.Is(err, ErrBootstrap):
		return "bootstrap-envelope-rejected"
	case errors.Is(err, standardlinux.ErrAdmission):
		return "policy-or-image-admission-rejected"
	case errors.Is(err, dockerengine.ErrConflict):
		return "runtime-ownership-or-config-conflict"
	case errors.Is(err, dockerengine.ErrUnavailable):
		return "runtime-unavailable"
	case errors.Is(err, agent.ErrCapacity):
		return "admission-pressure"
	case errors.Is(err, dockerengine.ErrStoragePressure):
		return "runtime-storage-pressure"
	case errors.Is(err, ErrReconcile), errors.Is(err, agent.ErrRecoveryRequired):
		return "reconciliation-required"
	default:
		return "operation-failed"
	}
}

func (c *Controller) trigger() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Run cancellation closes controller loops only, never runtime objects. Failed
// operations are repaired by complete periodic scans, not an unbounded queue.
func (c *Controller) Run(ctx context.Context) error {
	if c.Store == nil || c.Runtime == nil || c.Remote == nil || c.Policy == nil || c.VerifyImage == nil || c.Drained == nil {
		return ErrReconcile
	}
	c.wake = make(chan struct{}, 1)
	c.cancelled = make(map[agent.ExecutionCursor]bool)
	c.heartbeatGeneration.Store("1")
	// Retired history is never loaded into a recovery snapshot. A bounded-page
	// startup pass only removes private remnants left by a crash after cleanup
	// commit; receipts, final ACKs and permanent fences stay in SQLite.
	if err := c.retiredSecrets(ctx); err != nil {
		return err
	}
	var wg sync.WaitGroup
	launch := func(fn func(context.Context)) { wg.Add(1); go func() { defer wg.Done(); fn(ctx) }() }
	launch(c.commandLoop)
	launch(c.reportLoop)
	launch(func(ctx context.Context) {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			endpoint, err := c.Runtime.Probe(ctx)
			if err == nil && endpoint == c.Scope.EndpointIdentity {
				_ = c.Remote.Heartbeat(ctx, c.heartbeatGeneration.Load().(string))
			} else if ctx.Err() == nil {
				_ = c.Store.InvalidateRuntime(ctx)
				c.trigger()
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	})
	launch(func(ctx context.Context) {
		for ctx.Err() == nil {
			err := c.Runtime.Watch(ctx, c.trigger)
			if err != nil && ctx.Err() == nil {
				_ = c.Store.InvalidateRuntime(ctx)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	})
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	c.trigger()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case <-ticker.C:
			c.trigger()
		case <-c.wake:
			c.mu.Lock()
			_ = c.reconcile(ctx)
			c.mu.Unlock()
		}
	}
}

func (c *Controller) commandLoop(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			commands, err := c.Remote.Commands(ctx)
			if err != nil {
				continue
			}
			for _, raw := range commands {
				r, err := c.accept(ctx, raw)
				if err != nil {
					continue
				}
				_ = c.Remote.Ack(ctx, r)
				c.trigger()
			}
		}
	}
}

func (c *Controller) accept(ctx context.Context, raw json.RawMessage) (agent.Receipt, error) {
	r, err := c.Store.Receipt(ctx, c.Scope, raw)
	if err == nil {
		return r, nil
	}
	if !errors.Is(err, agent.ErrNotFound) {
		return r, err
	}
	var command struct {
		Kind string                 `json:"kind"`
		Spec protocol.ExecutionSpec `json:"spec"`
	}
	if json.Unmarshal(raw, &command) != nil {
		return agent.Receipt{}, ErrReconcile
	}
	if command.Kind == "start" && (command.Spec.PoolId != c.Pool || c.Drained() || c.admit(command.Spec, time.Now()) != nil || c.Remote.Admission(ctx, command.Spec) != nil) {
		return agent.Receipt{}, standardlinux.ErrAdmission
	}
	if err = c.activateLimits(ctx); err != nil {
		return agent.Receipt{}, err
	}
	if command.Kind == "start" {
		if err = c.runtimeHeadroom(ctx); err != nil {
			return agent.Receipt{}, err
		}
	}
	c.launchMu.Lock()
	defer c.launchMu.Unlock()
	receipt, err := c.Store.AcceptCommand(ctx, c.Scope, raw)
	if err == nil {
		// Do not wait for the external ACK before containing accepted cancellation.
		c.trigger()
	}
	return receipt, err
}

func (c *Controller) activateLimits(ctx context.Context) error {
	limits := c.Policy().Limits()
	if c.HostLimits != (agent.ReservationLimits{}) {
		limits = agent.ReservationLimits{CPUMillis: min(limits.CPUMillis, c.HostLimits.CPUMillis), MemoryBytes: min(limits.MemoryBytes, c.HostLimits.MemoryBytes), StorageBytes: min(limits.StorageBytes, c.HostLimits.StorageBytes), Slots: min(limits.Slots, c.HostLimits.Slots)}
	}
	return c.Store.SetReservationLimits(ctx, limits)
}

func (c *Controller) executions(ctx context.Context) ([]agent.Execution, error) {
	var out []agent.Execution
	cursor := agent.ExecutionCursor{}
	for {
		rows, err := c.Store.Incomplete(ctx, cursor, 100)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
		if len(out) > 1000 {
			return nil, ErrReconcile
		}
		if len(rows) < 100 {
			return out, nil
		}
		last := rows[len(rows)-1]
		cursor = agent.ExecutionCursor{ExecutionID: last.Identity.ExecutionID, Generation: last.Identity.Generation}
	}
}

func (c *Controller) refresh(ctx context.Context) ([]agent.Execution, error) {
	limits := c.Policy().Limits()
	if c.HostLimits != (agent.ReservationLimits{}) {
		limits = agent.ReservationLimits{CPUMillis: min(limits.CPUMillis, c.HostLimits.CPUMillis), MemoryBytes: min(limits.MemoryBytes, c.HostLimits.MemoryBytes), StorageBytes: min(limits.StorageBytes, c.HostLimits.StorageBytes), Slots: min(limits.Slots, c.HostLimits.Slots)}
	}
	if err := c.Store.SetReservationLimits(ctx, limits); err != nil {
		return nil, err
	}
	endpoint, err := c.Runtime.Probe(ctx)
	if err != nil || endpoint != c.Scope.EndpointIdentity {
		return nil, ErrReconcile
	}
	// A final durable ACK retires a local execution from active reconciliation.
	// Pending final facts remain explicit lookups even when SaaS already cleaned
	// the execution, so losing an ACK never loses its authoritative watermark.
	rows, err := c.executions(ctx)
	if err != nil {
		return nil, err
	}
	lookups := make([]agent.ExecutionCursor, 0, len(rows))
	for _, e := range rows {
		lookups = append(lookups, executionKey(e))
	}
	state, err := c.Remote.Recovery(ctx, lookups)
	if err != nil {
		return nil, err
	}
	if state.EndpointIdentity != c.Scope.EndpointIdentity || state.Identity.HostId != c.Scope.HostID || state.Identity.SessionEpoch != c.Scope.SessionEpoch || state.Identity.KeyId != c.Authority.KeyID {
		return nil, ErrReconcile
	}
	known := map[string]bool{}
	observations := []any{}
	for _, e := range rows {
		if len(e.RuntimeRef) > 0 {
			if err := c.Store.VerifyCreationClaim(ctx, c.Scope, e.Command); err != nil {
				return nil, err
			}
		}
		var start protocol.StartCommand
		if json.Unmarshal(e.Command, &start) != nil {
			return nil, ErrReconcile
		}
		plan, err := c.resolveRecoveryPlan(c.Scope, start.Spec)
		if err != nil {
			return nil, err
		}
		o, err := c.Runtime.Inspect(ctx, plan.Name, plan)
		if errors.Is(err, dockerengine.ErrAbsent) {
			continue
		}
		if err != nil {
			return nil, err
		}
		known[o.ID] = true
		if err = c.Store.VerifyCreationClaim(ctx, c.Scope, e.Command); err != nil {
			return nil, err
		}
		observations = append(observations, c.observation(e, o))
	}
	ids, err := c.Runtime.Inventory(ctx)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if !known[id] {
			return nil, ErrReconcile
		}
	}
	n, err := strconv.ParseUint(state.InventoryGeneration, 10, 64)
	if err != nil || n == ^uint64(0) {
		return nil, ErrReconcile
	}
	generation := strconv.FormatUint(n+1, 10)
	observed := time.Now().UTC().Truncate(time.Millisecond)
	message, err := protocol.EncodeValidated("InventorySnapshot", map[string]any{"inventoryGeneration": generation, "endpointIdentity": c.Scope.EndpointIdentity, "complete": true, "observedAt": observed.Format(wireTime), "resources": observations})
	if err != nil {
		return nil, err
	}
	if err = c.Remote.Inventory(ctx, message); err != nil {
		return nil, err
	}
	// Refresh cancellation and ACK state after publishing the complete inventory.
	state, err = c.Remote.Recovery(ctx, lookups)
	if err != nil {
		return nil, err
	}
	if state.InventoryGeneration != generation || state.EndpointIdentity != c.Scope.EndpointIdentity || state.Identity.HostId != c.Scope.HostID || state.Identity.SessionEpoch != c.Scope.SessionEpoch || state.Identity.KeyId != c.Authority.KeyID {
		return nil, ErrReconcile
	}
	watermarks := make([]agent.Watermark, 0, len(rows))
	indexed := make(map[agent.ExecutionCursor]protocol.RecoveryEntry, len(state.Entries))
	c.cancelled = map[agent.ExecutionCursor]bool{}
	for _, entry := range state.Entries {
		key := agent.ExecutionCursor{ExecutionID: entry.ExecutionId, Generation: entry.Generation}
		if _, duplicate := indexed[key]; duplicate {
			return nil, ErrReconcile
		}
		indexed[key] = entry
		c.cancelled[key] = entry.Cancelled
	}
	for _, e := range rows {
		r, found := indexed[executionKey(e)]
		if !found || r.CommandId != e.CommandID || r.SpecHash != e.Identity.SpecHash {
			return nil, ErrReconcile
		}
		watermarks = append(watermarks, agent.Watermark{ExecutionID: r.ExecutionId, Generation: r.Generation, ContiguousSequence: r.ContiguousSequence})
	}
	health := c.Store.Health(ctx)
	if err = c.Store.Reconcile(ctx, agent.RecoveryCheckpoint{JournalID: health.JournalID, Revision: health.Revision, Scope: c.Scope, InventoryGeneration: generation, ObservedAt: observed, ServerWatermarks: watermarks}); err != nil {
		return nil, err
	}
	c.inventoryGeneration = generation
	c.inventoryObservedAt = observed
	c.heartbeatGeneration.Store(generation)
	return rows, nil
}

func (c *Controller) reconcile(ctx context.Context) error {
	// Expired plaintext must not depend on platform availability or successful
	// runtime reconciliation. Recipient keys stay durable until cleanup is proven.
	c.expireHandoffs(ctx, time.Now())
	rows, err := c.refresh(ctx)
	if err != nil {
		c.status.Store(failureReason(err))
		_ = c.Store.InvalidateRuntime(ctx)
		return err
	}
	var firstError error
	for _, e := range rows {
		if e.State == "cleaned" {
			if p, e2 := c.plan(e); e2 == nil {
				c.cleanSecrets(e, p)
			}
		} else {
			if err = c.execution(ctx, e); err != nil {
				if firstError == nil {
					firstError = err
				}
				continue
			}
		}
	}
	if firstError != nil {
		c.status.Store(failureReason(firstError))
	} else {
		c.status.Store("ready")
	}
	return nil
}

func (c *Controller) expireHandoffs(ctx context.Context, now time.Time) {
	rows, err := c.executions(ctx)
	if err != nil {
		return
	}
	for _, e := range rows {
		p, err := c.plan(e)
		if err != nil {
			continue
		}
		dir := filepath.Join(c.Profile.BootstrapRoot, p.Name)
		raw, err := hostfs.ReadPrivate(filepath.Join(dir, "bootstrap.json"), 131072)
		if err != nil {
			continue
		}
		var handoff struct {
			ExpiresAt string `json:"expiresAt"`
		}
		err = json.Unmarshal(raw, &handoff)
		clear(raw)
		expires, parseErr := time.Parse(time.RFC3339Nano, handoff.ExpiresAt)
		if err != nil || parseErr != nil || expires.After(now) {
			continue
		}
		root, err := hostfs.OpenState(dir)
		if err == nil {
			_ = root.Remove("bootstrap.json")
			_ = root.Close()
		}
	}
}

func executionKey(e agent.Execution) agent.ExecutionCursor {
	return agent.ExecutionCursor{ExecutionID: e.Identity.ExecutionID, Generation: e.Identity.Generation}
}

func (c *Controller) observation(e agent.Execution, o dockerengine.Object) map[string]any {
	result := map[string]any{"runtimeRef": map[string]any{"engine": "docker", "scope": c.Scope.EndpointIdentity, "resourceKind": "container", "resourceId": o.ID, "executionId": e.Identity.ExecutionID, "generation": e.Identity.Generation, "specHash": e.Identity.SpecHash}, "state": o.State, "observedAt": time.Now().UTC().Format(wireTime)}
	if o.State == "exited" {
		result["exitCode"] = o.ExitCode
	}
	return result
}

func (c *Controller) event(e agent.Execution, observation map[string]any, provider any, never ...json.RawMessage) ([]byte, error) {
	n, err := strconv.ParseUint(e.LastSequence, 10, 64)
	if err != nil || n == ^uint64(0) {
		return nil, ErrReconcile
	}
	seq := strconv.FormatUint(n+1, 10)
	id := sha256.Sum256([]byte(e.Identity.ExecutionID + "\x00" + e.Identity.Generation + "\x00" + seq))
	v := map[string]any{"eventId": hex.EncodeToString(id[:]), "executionId": e.Identity.ExecutionID, "attemptId": e.Identity.AttemptID, "generation": e.Identity.Generation, "sequence": seq}
	if observation != nil {
		v["observation"] = observation
	}
	if provider != nil {
		v["providerObservation"] = provider
	}
	if len(never) == 1 {
		v["neverStarted"] = never[0]
	}
	v["payloadHash"] = strings.Repeat("0", 64)
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	digest, err := protocol.PayloadHashJSON("HostEvent", raw)
	if err != nil {
		return nil, err
	}
	v["payloadHash"] = digest
	message, err := protocol.EncodeValidated("HostEvent", v)
	if err != nil {
		return nil, err
	}
	return message.Bytes(), nil
}

func (c *Controller) execution(ctx context.Context, e agent.Execution) error {
	var start protocol.StartCommand
	if json.Unmarshal(e.Command, &start) != nil {
		return ErrReconcile
	}
	if start.Spec.PoolId != c.Pool {
		return standardlinux.ErrAdmission
	}
	p, err := c.resolveRecoveryPlan(c.Scope, start.Spec)
	if err != nil {
		return err
	}
	controls, err := c.Store.ControlCommands(ctx, e.Identity.ExecutionID, e.Identity.Generation)
	if err != nil {
		return err
	}
	var fence []byte
	for _, raw := range controls {
		var control struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(raw, &control) != nil {
			return ErrReconcile
		}
		if control.Kind == "cancel" || control.Kind == "cleanup" || control.Kind == "fence-never-started" {
			c.cancelled[executionKey(e)] = true
		}
		if control.Kind == "fence-never-started" {
			fence = raw
		}
	}
	o, err := c.Runtime.Inspect(ctx, p.Name, p)
	if err == nil {
		if err = c.Store.VerifyCreationClaim(ctx, c.Scope, e.Command); err != nil {
			return err
		}
		if len(e.RuntimeRef) == 0 {
			obs := c.observation(e, o)
			obs["state"] = "prepared"
			event, err := c.event(e, obs, nil)
			if err != nil {
				return err
			}
			return c.Store.RecordObservation(ctx, c.Scope, event)
		}
		if o.State == "exited" && e.State != "exited" && !e.CleanupPending {
			event, e2 := c.event(e, c.observation(e, o), nil)
			if e2 != nil {
				return e2
			}
			return c.Store.RecordObservation(ctx, c.Scope, event)
		}
		if e.CleanupPending || c.cancelled[executionKey(e)] || o.State == "exited" {
			return c.cleanup(ctx, e, p, o)
		}
		if o.State == "running" {
			if c.Kata != nil && !c.Kata.Healthy(p, o.StartedAt, time.Now()) {
				return c.cleanup(ctx, e, p, o)
			}
			if c.Kata != nil {
				if err = c.Kata.Capture(ctx, o.ID, p); err != nil {
					return err
				}
			}
			if e.State != "running" {
				event, err := c.event(e, c.observation(e, o), nil)
				if err != nil {
					return err
				}
				return c.Store.RecordObservation(ctx, c.Scope, event)
			}
			return c.registration(ctx, e, p)
		}
		if o.State != "prepared" {
			return ErrReconcile
		}
	} else if !errors.Is(err, dockerengine.ErrAbsent) {
		return err
	}
	if errors.Is(err, dockerengine.ErrAbsent) && len(e.RuntimeRef) == 0 && len(fence) > 0 {
		proof, e2 := c.Store.FenceNeverStarted(ctx, e.Command, fence, c.Authority, c.SigningKey, time.Now())
		if e2 != nil {
			return e2
		}
		if c.Kata != nil {
			if e2 = c.Kata.DiscardPrepared(ctx, p); e2 != nil {
				return e2
			}
		}
		event, e2 := c.event(e, nil, nil, proof)
		if e2 != nil {
			return e2
		}
		return c.Store.CompleteNeverStarted(ctx, c.Scope, event)
	}
	if e.CleanupPending && len(e.RuntimeRef) > 0 {
		return c.cleanup(ctx, e, p, dockerengine.Object{State: "exited"})
	}
	if c.cancelled[executionKey(e)] || c.Drained() {
		return ErrReconcile
	}
	if e.State != "accepted" && e.State != "prepared" {
		return ErrReconcile
	}
	if err = c.runtimeHeadroom(ctx); err != nil {
		return err
	}
	policy := c.Policy()
	if policy.UID() != c.Profile.RunnerUID {
		return standardlinux.ErrAdmission
	}
	if err = c.admit(start.Spec, time.Now()); err != nil {
		return err
	}
	p, err = c.resolvePlan(c.Scope, start.Spec)
	if err != nil {
		return err
	}
	if err = c.Remote.Admission(ctx, start.Spec); err != nil {
		return err
	}
	imageRepository := strings.Split(p.Config.Image, "@")[0]
	if err = c.VerifyImage(ctx, policy, imageRepository, start.Spec.ImageDigest, time.Now()); err != nil {
		return err
	}
	if err = c.Runtime.PrepareImage(ctx, p); err != nil {
		return err
	}
	if c.Kata != nil {
		if err = c.Kata.PrepareHealth(p); err != nil {
			return err
		}
		if err = c.Kata.Prepare(p); err != nil {
			return err
		}
	}
	request, key, err := c.startIntent(ctx, e, start)
	if err != nil {
		return err
	}
	response, err := c.Remote.Start(ctx, request)
	if err != nil {
		return err
	}
	if response.State != "ISSUED" || response.BootstrapExpiresAt == nil || response.RecoveryExpiresAt == nil || !response.EncryptedBootstrap.IsSpecified() || response.EncryptedBootstrap.IsNull() {
		return ErrReconcile
	}
	// SaaS seals delivery to recoveryExpiresAt, which can be earlier than the
	// provider credential's lifetime. Preserve that exact authenticated deadline.
	delivery, err := time.Parse(time.RFC3339Nano, *response.RecoveryExpiresAt)
	bootstrap, bootstrapErr := time.Parse(time.RFC3339Nano, *response.BootstrapExpiresAt)
	authority, authorityErr := time.Parse(time.RFC3339Nano, start.Spec.AuthorizationExpiresAt)
	if err != nil || bootstrapErr != nil || authorityErr != nil || !delivery.After(time.Now()) || delivery.After(bootstrap) || delivery.After(authority) {
		return ErrBootstrap
	}
	plain, err := transport.OpenBootstrap(response.EncryptedBootstrap.MustGet(), key, transport.BootstrapBinding{TenantID: c.Scope.TenantID, HostID: c.Scope.HostID, ExecutionID: e.Identity.ExecutionID, Generation: e.Identity.Generation, StartRequestID: requestID(e), SpecHash: e.Identity.SpecHash, ExpiresAt: *response.RecoveryExpiresAt}, time.Now())
	if err != nil {
		return ErrBootstrap
	}
	defer clear(plain)
	if err = c.handoff(p, plain, *response.RecoveryExpiresAt); err != nil {
		return err
	}
	authorize := func() error {
		if c.Kata != nil {
			if err := c.Kata.VerifyStorage(ctx, p); err != nil {
				return err
			}
		}
		if c.Drained() || c.cancelled[executionKey(e)] || c.Policy().UID() != c.Profile.RunnerUID {
			return ErrReconcile
		}
		if err := c.admit(start.Spec, time.Now()); err != nil {
			return err
		}
		if err := c.Remote.Admission(ctx, start.Spec); err != nil {
			return err
		}
		if err := c.activateLimits(ctx); err != nil {
			return err
		}
		if err := c.runtimeHeadroom(ctx); err != nil {
			return err
		}
		if err := c.VerifyImage(ctx, c.Policy(), imageRepository, start.Spec.ImageDigest, time.Now()); err != nil {
			return err
		}
		fresh, err := c.Remote.Start(ctx, request)
		if err != nil || fresh.State != "ISSUED" || fresh.IssuanceId != response.IssuanceId || fresh.RecoveryExpiresAt == nil || fresh.BootstrapExpiresAt == nil || *fresh.RecoveryExpiresAt != *response.RecoveryExpiresAt || *fresh.BootstrapExpiresAt != *response.BootstrapExpiresAt || !delivery.After(time.Now()) {
			return ErrReconcile
		}
		return c.Store.CheckLaunch(ctx, e.Command, c.Authority)
	}
	if err = authorize(); err != nil {
		return err
	}
	o, err = c.Runtime.Ensure(ctx, p, func() error {
		if err := authorize(); err != nil {
			return err
		}
		return c.Store.ClaimCreation(ctx, e.Command, c.Authority)
	})
	if err != nil {
		return err
	}
	if len(e.RuntimeRef) == 0 {
		obs := c.observation(e, o)
		obs["state"] = "prepared"
		event, e2 := c.event(e, obs, nil)
		if e2 != nil {
			return e2
		}
		if e2 = c.Store.RecordObservation(ctx, c.Scope, event); e2 != nil {
			return e2
		}
		e.State = "prepared"
		seq, _ := strconv.ParseUint(e.LastSequence, 10, 64)
		e.LastSequence = strconv.FormatUint(seq+1, 10)
	}
	// Linearization boundary: a cancellation already durably accepted wins the
	// final CheckLaunch. Once this lock is held, a concurrent command cannot be
	// accepted/ACKed until the bounded Docker start/inspection returns. Unknown
	// start replies remain the same attempt; accepted cancellation wakes cleanup.
	c.launchMu.Lock()
	if c.Kata != nil {
		if err = c.Kata.CapturePrepared(o.ID, p); err != nil {
			c.launchMu.Unlock()
			return err
		}
	}
	o, err = c.Runtime.Start(ctx, o.ID, p, func() error {
		if err := c.Store.VerifyCreationClaim(ctx, c.Scope, e.Command); err != nil {
			return err
		}
		return authorize()
	})
	c.launchMu.Unlock()
	if err != nil {
		return err
	}
	if c.Kata != nil {
		if err = c.Kata.Capture(ctx, o.ID, p); err != nil {
			return err
		}
	}
	event, err := c.event(e, c.observation(e, o), nil)
	if err != nil {
		return err
	}
	return c.Store.RecordObservation(ctx, c.Scope, event)
}

func (c *Controller) runtimeHeadroom(ctx context.Context) error {
	minimum := c.MinRuntimeFreeBytes
	if minimum == 0 {
		minimum = 256 << 20
	}
	return c.Runtime.CheckHeadroom(ctx, minimum)
}

func requestID(e agent.Execution) string {
	h := sha256.Sum256([]byte(e.CommandID + "\x00" + e.Identity.SpecHash))
	return hex.EncodeToString(h[:])
}

func (c *Controller) startIntent(ctx context.Context, e agent.Execution, start protocol.StartCommand) (protocol.Outbound, *ecdh.PrivateKey, error) {
	name := filepath.Join(c.KeysDirectory, requestID(e)+".key")
	raw, err := hostfs.ReadPrivate(name, 32)
	if err != nil {
		if len(e.StartRequest) > 0 {
			return protocol.Outbound{}, nil, ErrReconcile
		}
		key, e2 := ecdh.X25519().GenerateKey(rand.Reader)
		if e2 != nil {
			return protocol.Outbound{}, nil, e2
		}
		raw = key.Bytes()
		f, e2 := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e2 != nil {
			return protocol.Outbound{}, nil, ErrReconcile
		}
		_, e2 = f.Write(raw)
		if e2 == nil {
			e2 = f.Sync()
		}
		_ = f.Close()
		if e2 != nil {
			return protocol.Outbound{}, nil, ErrReconcile
		}
		dir, e2 := os.Open(c.KeysDirectory)
		if e2 != nil {
			return protocol.Outbound{}, nil, ErrReconcile
		}
		e2 = dir.Sync()
		_ = dir.Close()
		if e2 != nil {
			return protocol.Outbound{}, nil, ErrReconcile
		}
	}
	defer clear(raw)
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return protocol.Outbound{}, nil, ErrReconcile
	}
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	request, err := protocol.EncodeValidated("StartRequest", map[string]any{"executionId": e.Identity.ExecutionID, "attemptId": e.Identity.AttemptID, "generation": e.Identity.Generation, "commandId": e.CommandID, "startRequestId": requestID(e), "specHash": e.Identity.SpecHash, "policyGeneration": start.Spec.PolicyGeneration, "bootstrapPublicKey": public})
	if err != nil {
		return protocol.Outbound{}, nil, err
	}
	if err = c.Store.PutStartIntent(ctx, c.Scope, request.Bytes()); err != nil {
		return protocol.Outbound{}, nil, err
	}
	return request, key, nil
}

func (c *Controller) handoff(p dockerengine.Plan, plain []byte, expires string) error {
	dir := filepath.Join(c.Profile.BootstrapRoot, p.Name)
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return ErrReconcile
	}
	root, err := hostfs.OpenState(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	raw, err := json.Marshal(map[string]any{"jit": string(plain), "expiresAt": expires, "organization": c.Organization, "repository": c.Repository, "pool": c.Pool})
	if err != nil {
		return err
	}
	defer clear(raw)
	if existing, e := hostfs.ReadPrivate(filepath.Join(dir, "bootstrap.json"), 131072); e == nil {
		defer clear(existing)
		if string(existing) == string(raw) {
			return nil
		}
		return ErrReconcile
	}
	f, err := root.OpenFile("bootstrap.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrReconcile
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	_ = f.Close()
	return err
}

func (c *Controller) registration(ctx context.Context, e agent.Execution, p dockerengine.Plan) error {
	raw, err := hostfs.ReadPrivate(filepath.Join(c.Profile.BootstrapRoot, p.Name, "registered.json"), 8192)
	if err != nil {
		return nil
	}
	observation, err := protocol.DecodeProviderObservation(raw)
	if err != nil || observation.Provider != "github" || observation.Organization != c.Organization || observation.Pool != c.Pool {
		return ErrReconcile
	}
	// Only the first registration fact is emitted; the source marker remains for
	// diagnosis. Platform issuance independently corroborates the runner identity.
	if e.LastSequence != "2" {
		return nil
	}
	event, err := c.event(e, nil, observation)
	if err != nil {
		return err
	}
	return c.Store.RecordObservation(ctx, c.Scope, event)
}

func (c *Controller) cleanup(ctx context.Context, e agent.Execution, p dockerengine.Plan, o dockerengine.Object) error {
	if c.Kata != nil && o.State == "prepared" {
		if err := c.Kata.CapturePrepared(o.ID, p); err != nil {
			return err
		}
	}
	if !e.CleanupPending {
		obs := c.observation(e, o)
		obs["state"] = "cleanup-pending"
		event, err := c.event(e, obs, nil)
		if err != nil {
			return err
		}
		if err = c.Store.RequireCleanup(ctx, c.Scope, event); err != nil {
			return err
		}
		n, _ := strconv.ParseUint(e.LastSequence, 10, 64)
		e.LastSequence = strconv.FormatUint(n+1, 10)
		e.CleanupPending = true
		raw, _ := json.Marshal(obs["runtimeRef"])
		e.RuntimeRef = raw
	}
	var ref protocol.RuntimeRef
	if json.Unmarshal(e.RuntimeRef, &ref) != nil || ref.ResourceId == "" {
		return ErrReconcile
	}
	if err := c.Runtime.Stop(ctx, ref.ResourceId, p); err != nil {
		return err
	}
	controls, err := c.Store.ControlCommands(ctx, e.Identity.ExecutionID, e.Identity.Generation)
	if err != nil {
		return err
	}
	cleanupAuthorized := false
	for _, raw := range controls {
		var command struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(raw, &command) != nil {
			return ErrReconcile
		}
		if command.Kind == "cleanup" {
			cleanupAuthorized = true
		}
	}
	if !cleanupAuthorized {
		return ErrReconcile
	}
	if err := c.Runtime.Remove(ctx, ref.ResourceId, p); err != nil {
		return err
	}
	if _, err := c.Runtime.Inspect(ctx, ref.ResourceId, p); !errors.Is(err, dockerengine.ErrAbsent) {
		return ErrReconcile
	}
	// Complete inventory plus authenticated platform reconciliation refreshes the
	// endpoint after remove; any disconnect leaves the obligation unresolved.
	if _, err := c.refresh(ctx); err != nil {
		return err
	}
	if err := verifyKataAbsence(ctx, c.Kata, c.Runtime, ref.ResourceId, p); err != nil {
		return err
	}
	observed := c.inventoryObservedAt
	o.ID = ref.ResourceId
	o.State = "cleaned"
	obs := c.observation(e, o)
	obs["observedAt"] = observed.Format(wireTime)
	event, err := c.event(e, obs, nil)
	if err != nil {
		return err
	}
	if err = c.Store.CompleteCleanup(ctx, c.Scope, event, agent.AbsenceEvidence{RuntimeRef: e.RuntimeRef, EndpointIdentity: c.Scope.EndpointIdentity, InventoryGeneration: c.inventoryGeneration, ObservedAt: observed}); err != nil {
		return err
	}
	c.cleanSecrets(e, p)
	return nil
}

func (c *Controller) plan(e agent.Execution) (dockerengine.Plan, error) {
	start, err := c.storedStart(e)
	if err != nil {
		return dockerengine.Plan{}, err
	}
	return c.resolveRecoveryPlan(c.Scope, start.Spec)
}

func (c *Controller) storedStart(e agent.Execution) (protocol.StartCommand, error) {
	// Retired housekeeping must not map inconsistent stored metadata to another
	// attempt's private files, even before current-session reconciliation.
	if err := protocol.ValidateInboundJSON("StartCommand", e.Command); err != nil {
		return protocol.StartCommand{}, ErrReconcile
	}
	var start protocol.StartCommand
	if json.Unmarshal(e.Command, &start) != nil {
		return protocol.StartCommand{}, ErrReconcile
	}
	if e.Identity.InstallationID != c.Scope.InstallationID || e.Identity.TenantID != c.Scope.TenantID || e.Identity.HostID != c.Scope.HostID || start.CommandId != e.CommandID || start.Spec.ExecutionId != e.Identity.ExecutionID || start.Generation != e.Identity.Generation || start.Spec.Generation != e.Identity.Generation || start.Spec.AttemptId != e.Identity.AttemptID || start.Spec.SpecHash != e.Identity.SpecHash {
		return protocol.StartCommand{}, ErrReconcile
	}
	return start, nil
}

// Final-ACKed history needs only its immutable private namespace, not an active
// runtime profile. This deliberately returns no runnable Docker configuration.
// Unresolved work still uses plan() and the exact historical runtime contract.
func (c *Controller) retiredPrivatePlan(e agent.Execution) (dockerengine.Plan, error) {
	if e.State != "cleaned" || e.CleanupPending || e.AckSequence != e.LastSequence {
		return dockerengine.Plan{}, ErrReconcile
	}
	start, err := c.storedStart(e)
	if err != nil {
		return dockerengine.Plan{}, err
	}
	p, err := c.Profile.Plan(c.Scope, start.Spec)
	if err != nil {
		return dockerengine.Plan{}, err
	}
	return dockerengine.Plan{Name: p.Name, RecoveryOnly: true}, nil
}

func (c *Controller) cleanSecrets(e agent.Execution, p dockerengine.Plan) {
	// Host tmpfs holds only this execution's bootstrap/registration files. Never
	// recursively remove a caller-provided path or any shared runtime resource.
	dir := filepath.Join(c.Profile.BootstrapRoot, p.Name)
	root, err := hostfs.OpenState(dir)
	if err == nil {
		_ = root.Remove("bootstrap.json")
		_ = root.Remove("registered.json")
		_ = root.Close()
		// rmdir only: unexpected files are preserved, never recursively pruned.
		_ = os.Remove(dir)
	}
	if c.Kata != nil {
		c.Kata.CleanHealth(p)
	}
	keys, err := hostfs.OpenState(c.KeysDirectory)
	if err == nil {
		_ = keys.Remove(requestID(e) + ".key")
		_ = keys.Close()
	}
}

func (c *Controller) retiredSecrets(ctx context.Context) error {
	cursor := agent.ExecutionCursor{}
	for {
		rows, err := c.Store.Executions(ctx, cursor, 100)
		if err != nil {
			return err
		}
		for _, e := range rows {
			if e.State == "cleaned" && !e.CleanupPending {
				p, err := c.plan(e)
				if e.AckSequence == e.LastSequence {
					p, err = c.retiredPrivatePlan(e)
				}
				if err != nil {
					return err
				}
				c.cleanSecrets(e, p)
			}
		}
		if len(rows) < 100 {
			return nil
		}
		cursor = executionKey(rows[len(rows)-1])
	}
}

func (c *Controller) reportLoop(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rows, err := c.executions(ctx)
			if err != nil {
				continue
			}
			for _, e := range rows {
				events, err := c.Store.PendingEvents(ctx, agent.EventPage{ExecutionID: e.Identity.ExecutionID, Generation: e.Identity.Generation, AfterSequence: e.AckSequence, Limit: 100})
				if err != nil || len(events) == 0 {
					continue
				}
				message, err := protocol.EncodeValidated("EventBatch", map[string]any{"events": events})
				if err != nil {
					continue
				}
				acks, err := c.Remote.Events(ctx, message)
				if err != nil {
					continue
				}
				for _, ack := range acks {
					if ack.ExecutionId == e.Identity.ExecutionID && ack.Generation == e.Identity.Generation {
						_ = c.Store.AckEvents(ctx, c.Scope, agent.Watermark{ExecutionID: ack.ExecutionId, Generation: ack.Generation, ContiguousSequence: ack.ContiguousSequence})
					}
				}
			}
		}
	}
}
