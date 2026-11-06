package journal

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
)

// ApplyPeerRecovery records an exact independently approved, authenticated peer
// transition before any Docker mutation. It never changes origin commands,
// creation markers, runtime refs, event bytes or reservations. Ordinary admission
// remains blocked by the durable open-approval row, including after restart.
func (s *SQLiteStore) ApplyPeerRecovery(ctx context.Context, a *peerrecovery.Authorization) error {
	if !a.Current(time.Now()) {
		return agent.ErrRecoveryRequired
	}
	value, err := a.Approval().Value()
	if err != nil {
		return agent.ErrRecoveryRequired
	}
	plan := value.Manifest.Plan
	scope := agent.StoreScope{InstallationID: plan.InstallationId, TenantID: plan.Challenge.TenantId, HostID: plan.Challenge.Identity.HostId, SessionEpoch: plan.Challenge.Identity.SessionEpoch, EndpointIdentity: plan.TargetEndpointIdentity}
	if !validScope(scope) {
		return agent.ErrConflict
	}
	raw, err := peerrecovery.Canonical(value)
	if err != nil {
		return agent.ErrConflict
	}
	return s.transaction(ctx, false, false, true, func(ctx context.Context, tx *sql.Tx) error {
		if !a.Current(time.Now()) {
			return agent.ErrRecoveryRequired
		}
		var storedHash string
		var complete, superseded bool
		err := tx.QueryRowContext(ctx, "SELECT approval_hash,completed,superseded FROM peer_recovery_approvals WHERE approval_id=?", value.Manifest.ApprovalId).Scan(&storedHash, &complete, &superseded)
		if err == nil {
			if storedHash != a.Approval().Hash() || complete || superseded {
				return agent.ErrConflict
			}
			// Repeated application cannot reset ACKs, recreate work or alter authority.
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if plan.JournalId != s.anchor.JournalID || plan.JournalRevision != strconv.FormatInt(s.anchor.Revision, 10) {
			return agent.ErrRecoveryRequired
		}
		var oldRaw []byte
		if err = tx.QueryRowContext(ctx, "SELECT scope FROM metadata WHERE singleton=1").Scan(&oldRaw); err != nil {
			return err
		}
		var old agent.StoreScope
		if json.Unmarshal(oldRaw, &old) != nil || old.InstallationID != scope.InstallationID || old.TenantID != scope.TenantID || old.HostID != scope.HostID || padded(old.SessionEpoch) > padded(scope.SessionEpoch) {
			return agent.ErrConflict
		}
		if old.EndpointIdentity != plan.SourceEndpointIdentity {
			var priorRaw []byte
			var priorHash string
			if err = tx.QueryRowContext(ctx, "SELECT approval,approval_hash FROM peer_recovery_approvals WHERE completed=0 AND superseded=0").Scan(&priorRaw, &priorHash); err != nil {
				return agent.ErrRecoveryRequired
			}
			prior, e := protocol.DecodeSignedPeerRecoveryApproval(priorRaw)
			if e != nil {
				return agent.ErrRecoveryRequired
			}
			hash, e := peerrecovery.Hash(prior)
			if e != nil || hash != priorHash || prior.Manifest.Plan.TargetEndpointIdentity != old.EndpointIdentity || prior.Manifest.Plan.SourceEndpointIdentity != plan.SourceEndpointIdentity {
				return agent.ErrRecoveryRequired
			}
		}
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM executions WHERE state<>'cleaned' OR cleanup_pending=1 OR last_sequence>ack_sequence").Scan(&count); err != nil {
			return err
		}
		if count != len(plan.Executions) {
			return agent.ErrRecoveryRequired
		}
		for _, execution := range plan.Executions {
			if err = s.matchRecoveryExecution(ctx, tx, plan, execution); err != nil {
				return err
			}
		}
		for _, w := range a.Watermarks() {
			if err = ack(ctx, tx, agent.Watermark{ExecutionID: w.ExecutionId, Generation: w.Generation, ContiguousSequence: w.ContiguousSequence}); err != nil {
				return err
			}
		}
		// Superseding an approval retires its mutation authority, not its unfinished
		// obligations. Original executions and reservations remain untouched.
		if _, err = tx.ExecContext(ctx, "UPDATE peer_recovery_approvals SET superseded=1 WHERE completed=0 AND superseded=0"); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO peer_recovery_approvals(approval_id,approval_hash,approval,applied_revision) VALUES(?,?,?,?)", value.Manifest.ApprovalId, a.Approval().Hash(), raw, s.anchor.Revision+1); err != nil {
			return sqlConflict(err)
		}
		encoded, _ := json.Marshal(scope)
		_, err = tx.ExecContext(ctx, "UPDATE metadata SET scope=?,runtime_known=0,inventory_observed_at='' WHERE singleton=1", encoded)
		return err
	}, func() {
		s.scope = scope
		s.sessionReady = true
		s.ready = false
		s.reconciledGeneration = s.runtimeGeneration.Load()
		s.inventoryObservedAt = time.Time{}
	})
}

func (s *SQLiteStore) matchRecoveryExecution(ctx context.Context, tx *sql.Tx, plan protocol.PeerRecoveryPlan, e protocol.PeerRecoveryExecutionPlan) error {
	var command, identity, ref []byte
	var epoch, endpoint, state, last, acked string
	if err := tx.QueryRowContext(ctx, "SELECT identity,command,session_epoch,endpoint_identity,state,last_sequence,ack_sequence,runtime_ref FROM executions WHERE execution_id=? AND generation=?", e.ExecutionId, e.Generation).Scan(&identity, &command, &epoch, &endpoint, &state, &last, &acked, &ref); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return agent.ErrRecoveryRequired
		}
		return err
	}
	var id agent.Identity
	start, err := protocol.DecodeStartCommand(command)
	if err != nil || protocol.ValidateInboundJSON("StartCommand", command) != nil || start.Spec.ExecutionId != e.ExecutionId || start.Generation != e.Generation || start.Spec.Generation != e.Generation {
		return agent.ErrRecoveryRequired
	}
	if err != nil || json.Unmarshal(identity, &id) != nil || id.InstallationID != plan.InstallationId || id.TenantID != plan.Challenge.TenantId || id.HostID != plan.Challenge.Identity.HostId || id.ExecutionID != e.ExecutionId || id.Generation != e.Generation || id.SpecHash != e.SpecHash || start.PayloadHash != e.StartCommandHash || start.Spec.SpecHash != e.SpecHash || epoch != e.OriginalSessionEpoch || endpoint != plan.SourceEndpointIdentity || state != e.NativeState || unpad(last) != e.LastSequence || unpad(acked) != e.AckSequence {
		return agent.ErrRecoveryRequired
	}
	var commandHash, commandExecution, commandGeneration, commandKind string
	var commandPayload []byte
	if err = tx.QueryRowContext(ctx, "SELECT payload_hash,execution_id,generation,kind,payload FROM commands WHERE command_id=?", start.CommandId).Scan(&commandHash, &commandExecution, &commandGeneration, &commandKind, &commandPayload); err != nil {
		return agent.ErrStoreUnavailable
	}
	if commandHash != start.PayloadHash || commandExecution != e.ExecutionId || commandGeneration != e.Generation || commandKind != "start" || !bytes.Equal(commandPayload, command) || id.AttemptID != start.Spec.AttemptId {
		return agent.ErrStoreUnavailable
	}
	if padded(e.LastSequence) != last || padded(e.AckSequence) != acked {
		return agent.ErrStoreUnavailable
	}
	if e.OriginalRuntimeRef == nil {
		if len(ref) != 0 {
			return agent.ErrRecoveryRequired
		}
	} else {
		want, _ := peerrecovery.Canonical(e.OriginalRuntimeRef)
		actual, _ := protocol.CanonicalizeJSON(ref)
		if !bytes.Equal(want, actual) {
			return agent.ErrRecoveryRequired
		}
	}
	rows, err := tx.QueryContext(ctx, "SELECT event_id,sequence,payload_hash FROM outbox_events WHERE execution_id=? AND generation=? AND payload IS NOT NULL ORDER BY sequence", e.ExecutionId, e.Generation)
	if err != nil {
		return err
	}
	index := 0
	for rows.Next() {
		var event, seq, digest string
		if err = rows.Scan(&event, &seq, &digest); err != nil {
			rows.Close()
			return err
		}
		if index >= len(e.PendingEvents) || e.PendingEvents[index].EventId != event || e.PendingEvents[index].Sequence != unpad(seq) || e.PendingEvents[index].PayloadHash != digest {
			rows.Close()
			return agent.ErrRecoveryRequired
		}
		index++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if index != len(e.PendingEvents) {
		return agent.ErrRecoveryRequired
	}
	if e.CreationClaim == "verified" {
		startMap, err := decode("StartCommand", command)
		if err != nil {
			return agent.ErrRecoveryRequired
		}
		binding, err := binding(startMap, Authority{TenantID: id.TenantID, HostID: id.HostID, SessionEpoch: epoch, EndpointIdentity: endpoint, KeyID: "original-creation"})
		if err != nil {
			return agent.ErrRecoveryRequired
		}
		name, err := hash(map[string]string{"tenantId": id.TenantID, "hostId": id.HostID, "executionId": id.ExecutionID, "generation": id.Generation})
		if err != nil {
			return agent.ErrRecoveryRequired
		}
		raw, err := hostfs.ReadPrivate(filepath.Join(s.dir, name+".creation.json"), 8192)
		if err != nil {
			return agent.ErrRecoveryRequired
		}
		var marker record
		if json.Unmarshal(raw, &marker) != nil || marker.State != "CREATION_CLAIMED" {
			return agent.ErrRecoveryRequired
		}
		want, _ := hash(binding)
		got, _ := hash(marker.Binding)
		if want != got {
			return agent.ErrRecoveryRequired
		}
	}
	return nil
}

// CurrentPeerRecovery returns immutable signed public scope for diagnosis. It
// grants no mutation permission and remains usable before normal reconciliation.
func (s *SQLiteStore) CurrentPeerRecovery(ctx context.Context) (protocol.SignedPeerRecoveryApproval, error) {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return protocol.SignedPeerRecoveryApproval{}, err
	}
	defer release()
	if s.failed.Load() {
		return protocol.SignedPeerRecoveryApproval{}, agent.ErrStoreUnavailable
	}
	if err = s.peerRecoveryIntegrity(ctx); err != nil {
		return protocol.SignedPeerRecoveryApproval{}, s.receiptReadFailure(ctx, err)
	}
	var raw []byte
	if err = s.db.QueryRowContext(ctx, "SELECT approval FROM peer_recovery_approvals WHERE completed=0 AND superseded=0").Scan(&raw); errors.Is(err, sql.ErrNoRows) {
		return protocol.SignedPeerRecoveryApproval{}, agent.ErrNotFound
	} else if err != nil {
		return protocol.SignedPeerRecoveryApproval{}, s.receiptReadFailure(ctx, err)
	}
	value, err := protocol.DecodeSignedPeerRecoveryApproval(raw)
	if err != nil {
		return value, agent.ErrStoreUnavailable
	}
	return value, nil
}

// CheckPeerRecoveryMutation binds a fresh authenticated authorization to the
// durably applied approval and an already persisted cleanup obligation. A grant
// never authorizes a runtime action before RequireCleanup has committed.
func (s *SQLiteStore) CheckPeerRecoveryMutation(ctx context.Context, a *peerrecovery.Authorization, executionID, generation string) error {
	if !a.Current(time.Now()) {
		return agent.ErrRecoveryRequired
	}
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	if s.failed.Load() {
		return agent.ErrStoreUnavailable
	}
	if err = s.peerRecoveryIntegrity(ctx); err != nil {
		return s.receiptReadFailure(ctx, err)
	}
	var digest string
	var pending bool
	err = s.db.QueryRowContext(ctx, "SELECT a.approval_hash,e.cleanup_pending FROM peer_recovery_approvals a JOIN executions e ON e.execution_id=? AND e.generation=? WHERE a.completed=0 AND a.superseded=0", executionID, generation).Scan(&digest, &pending)
	if errors.Is(err, sql.ErrNoRows) {
		return agent.ErrRecoveryRequired
	}
	if err != nil {
		return s.receiptReadFailure(ctx, err)
	}
	if digest != a.Approval().Hash() || !pending {
		return agent.ErrRecoveryRequired
	}
	allowed, err := s.recoveryPermission(ctx, s.db, executionID, generation)
	if err != nil {
		return err
	}
	if allowed == nil || allowed.Action == "hold" || allowed.Action == "replay-final-ack" {
		return agent.ErrRecoveryRequired
	}
	return nil
}

type recoveryReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// nil means ordinary non-recovery operation. Once a recovery row exists, an
// omitted execution or hold decision always rejects, never falls back to normal.
func (s *SQLiteStore) recoveryPermission(ctx context.Context, reader recoveryReader, id, generation string) (*protocol.PeerRecoveryDecision, error) {
	var raw []byte
	var digest string
	err := reader.QueryRowContext(ctx, "SELECT approval,approval_hash FROM peer_recovery_approvals WHERE completed=0 AND superseded=0").Scan(&raw, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	approval, err := protocol.DecodeSignedPeerRecoveryApproval(raw)
	if err != nil {
		return nil, agent.ErrRecoveryRequired
	}
	actual, err := peerrecovery.Hash(approval)
	if err != nil || actual != digest {
		return nil, agent.ErrRecoveryRequired
	}
	expires, err := time.Parse(time.RFC3339Nano, approval.Manifest.ExpiresAt)
	if err != nil || !expires.After(time.Now()) || approval.Manifest.Plan.Challenge.Identity.SessionEpoch != s.scope.SessionEpoch || approval.Manifest.Plan.TargetEndpointIdentity != s.scope.EndpointIdentity {
		return nil, agent.ErrRecoveryRequired
	}
	for _, decision := range approval.Manifest.Decisions {
		if decision.ExecutionId == id && decision.Generation == generation {
			if decision.Action == "hold" {
				return nil, agent.ErrRecoveryRequired
			}
			return &decision, nil
		}
	}
	return nil, agent.ErrRecoveryRequired
}

// PeerRecoveryProgress reads only the exact frozen execution set; lifetime
// history does not affect recovery authorization cost. No caller-supplied ACK or
// row count can stand in for these native durable counters.
func (s *SQLiteStore) PeerRecoveryProgress(ctx context.Context, plan protocol.PeerRecoveryPlan) ([]peerrecovery.NativeProgress, error) {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if s.failed.Load() {
		return nil, agent.ErrStoreUnavailable
	}
	if err = s.peerRecoveryIntegrity(ctx); err != nil {
		return nil, s.receiptReadFailure(ctx, err)
	}
	if plan.JournalId != s.anchor.JournalID {
		return nil, agent.ErrRecoveryRequired
	}
	out := make([]peerrecovery.NativeProgress, 0, len(plan.Executions))
	for _, e := range plan.Executions {
		var last, ack string
		if err = s.db.QueryRowContext(ctx, "SELECT last_sequence,ack_sequence FROM executions WHERE execution_id=? AND generation=?", e.ExecutionId, e.Generation).Scan(&last, &ack); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, agent.ErrRecoveryRequired
			}
			return nil, s.receiptReadFailure(ctx, err)
		}
		out = append(out, peerrecovery.NativeProgress{ExecutionID: e.ExecutionId, Generation: e.Generation, LastSequence: unpad(last), AckSequence: unpad(ack)})
	}
	return out, nil
}

// CompletePeerRecovery retires only a completed, acknowledged transition after
// a fresh empty owned-resource inventory and authenticated platform completion.
// It never removes the local drain marker or grants production qualification.
func (s *SQLiteStore) CompletePeerRecovery(ctx context.Context, c *peerrecovery.Completion, checkpoint agent.RecoveryCheckpoint) error {
	if !c.Current(time.Now()) || !fresh(checkpoint.ObservedAt) {
		return agent.ErrRecoveryRequired
	}
	return s.write(ctx, false, false, func(ctx context.Context, tx *sql.Tx) error {
		if !c.Current(time.Now()) || checkpoint.Scope != s.scope || checkpoint.JournalID != s.anchor.JournalID || checkpoint.Revision != strconv.FormatInt(s.anchor.Revision, 10) {
			return agent.ErrRecoveryRequired
		}
		var generation string
		var known bool
		if err := tx.QueryRowContext(ctx, "SELECT inventory_generation,runtime_known FROM metadata WHERE singleton=1").Scan(&generation, &known); err != nil {
			return err
		}
		if !known || generation != checkpoint.InventoryGeneration {
			return agent.ErrRecoveryRequired
		}
		var digest string
		if err := tx.QueryRowContext(ctx, "SELECT approval_hash FROM peer_recovery_approvals WHERE completed=0 AND superseded=0").Scan(&digest); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return agent.ErrNotFound
			}
			return err
		}
		if digest != c.ApprovalHash() {
			return agent.ErrConflict
		}
		var unresolved, reserved int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM executions WHERE state<>'cleaned' OR cleanup_pending=1 OR last_sequence<>ack_sequence").Scan(&unresolved); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM reservations WHERE released=0").Scan(&reserved); err != nil {
			return err
		}
		if unresolved != 0 || reserved != 0 {
			return agent.ErrRecoveryRequired
		}
		var raw []byte
		if err := tx.QueryRowContext(ctx, "SELECT approval FROM peer_recovery_approvals WHERE completed=0 AND superseded=0").Scan(&raw); err != nil {
			return err
		}
		a, err := protocol.DecodeSignedPeerRecoveryApproval(raw)
		if err != nil {
			return agent.ErrRecoveryRequired
		}
		for _, d := range a.Manifest.Decisions {
			if d.Action == "hold" {
				return agent.ErrRecoveryRequired
			}
		}
		_, err = tx.ExecContext(ctx, "UPDATE peer_recovery_approvals SET completed=1 WHERE completed=0 AND superseded=0")
		return err
	})
}

func (s *SQLiteStore) PeerRecoveryScope(ctx context.Context) (agent.StoreScope, error) {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return agent.StoreScope{}, err
	}
	defer release()
	if s.failed.Load() {
		return agent.StoreScope{}, agent.ErrStoreUnavailable
	}
	if err = s.peerRecoveryIntegrity(ctx); err != nil {
		return agent.StoreScope{}, s.receiptReadFailure(ctx, err)
	}
	var raw []byte
	if err = s.db.QueryRowContext(ctx, "SELECT scope FROM metadata WHERE singleton=1").Scan(&raw); err != nil {
		return agent.StoreScope{}, s.receiptReadFailure(ctx, err)
	}
	var scope agent.StoreScope
	if json.Unmarshal(raw, &scope) != nil || !validScope(scope) {
		return scope, agent.ErrRecoveryRequired
	}
	var approvedRaw []byte
	err = s.db.QueryRowContext(ctx, "SELECT approval FROM peer_recovery_approvals WHERE completed=0 AND superseded=0").Scan(&approvedRaw)
	if err == nil {
		a, e := protocol.DecodeSignedPeerRecoveryApproval(approvedRaw)
		if e != nil {
			return scope, agent.ErrRecoveryRequired
		}
		var outstanding int
		if err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM executions WHERE state<>'cleaned' OR cleanup_pending=1 OR last_sequence>ack_sequence").Scan(&outstanding); err != nil {
			return scope, s.receiptReadFailure(ctx, err)
		}
		if outstanding > 0 {
			scope.EndpointIdentity = a.Manifest.Plan.SourceEndpointIdentity
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return scope, s.receiptReadFailure(ctx, err)
	}
	return scope, nil
}

func (s *SQLiteStore) PeerRecoveryPending(ctx context.Context, id, generation, after string, limit int) ([]json.RawMessage, error) {
	return s.pendingEvents(ctx, agent.EventPage{ExecutionID: id, Generation: generation, AfterSequence: after, Limit: limit}, false)
}
func (s *SQLiteStore) PeerRecoveryExecutionScope(ctx context.Context, id, generation string) (agent.StoreScope, error) {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return agent.StoreScope{}, err
	}
	defer release()
	if err = s.peerRecoveryIntegrity(ctx); err != nil {
		return agent.StoreScope{}, s.receiptReadFailure(ctx, err)
	}
	var raw []byte
	var epoch, endpoint string
	err = s.db.QueryRowContext(ctx, "SELECT identity,session_epoch,endpoint_identity FROM executions WHERE execution_id=? AND generation=?", id, generation).Scan(&raw, &epoch, &endpoint)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return agent.StoreScope{}, agent.ErrNotFound
		}
		return agent.StoreScope{}, s.receiptReadFailure(ctx, err)
	}
	var identity agent.Identity
	if json.Unmarshal(raw, &identity) != nil {
		return agent.StoreScope{}, agent.ErrStoreUnavailable
	}
	return agent.StoreScope{InstallationID: identity.InstallationID, TenantID: identity.TenantID, HostID: identity.HostID, SessionEpoch: epoch, EndpointIdentity: endpoint}, nil
}

// A known lagging anchor is visible only for operator-reviewed reconciliation;
// ordinary receipt/admission paths continue to reject it. A different identity,
// future anchor, missing file or database revision mismatch still fails closed.
func (s *SQLiteStore) peerRecoveryIntegrity(ctx context.Context) error {
	if s.failed.Load() {
		return agent.ErrStoreUnavailable
	}
	if !s.anchorUncertain {
		return s.receiptIntegrity(ctx)
	}
	if err := s.checkFiles(); err != nil {
		return err
	}
	raw, err := hostfs.ReadPrivate(filepath.Join(s.dir, anchorName), 4096)
	if err != nil {
		return err
	}
	var disk, actual anchor
	if json.Unmarshal(raw, &disk) != nil || disk.JournalID != s.anchor.JournalID || disk.Revision < 0 || disk.Revision > s.anchor.Revision {
		return agent.ErrRecoveryRequired
	}
	if err = s.db.QueryRowContext(ctx, "SELECT journal_id,revision FROM metadata WHERE singleton=1").Scan(&actual.JournalID, &actual.Revision); err != nil {
		return err
	}
	if actual != s.anchor {
		return agent.ErrRecoveryRequired
	}
	return nil
}

func (s *SQLiteStore) PeerRecoveryExecution(ctx context.Context, id, generation string) (agent.Execution, error) {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return agent.Execution{}, err
	}
	defer release()
	if err = s.peerRecoveryIntegrity(ctx); err != nil {
		return agent.Execution{}, err
	}
	var e agent.Execution
	var identity, command, request, ref []byte
	err = s.db.QueryRowContext(ctx, `SELECT e.identity,e.command_id,e.command,i.request,e.state,e.runtime_ref,e.cleanup_pending,e.last_sequence,e.ack_sequence FROM executions e LEFT JOIN start_intents i USING(execution_id,generation) WHERE e.execution_id=? AND e.generation=?`, id, generation).Scan(&identity, &e.CommandID, &command, &request, &e.State, &ref, &e.CleanupPending, &e.LastSequence, &e.AckSequence)
	if errors.Is(err, sql.ErrNoRows) {
		return e, agent.ErrNotFound
	}
	if err != nil {
		return e, s.receiptReadFailure(ctx, err)
	}
	if json.Unmarshal(identity, &e.Identity) != nil {
		return e, agent.ErrStoreUnavailable
	}
	e.Command = command
	e.StartRequest = request
	e.RuntimeRef = ref
	e.LastSequence = unpad(e.LastSequence)
	e.AckSequence = unpad(e.AckSequence)
	return e, nil
}

// CompletedPeerRecovery makes a lost final reply recoverable without reopening
// mutation authority. A superseded approval is not a completed transition.
func (s *SQLiteStore) CompletedPeerRecovery(ctx context.Context, approved *peerrecovery.OperatorApproval) (bool, error) {
	value, err := approved.Value()
	if err != nil {
		return false, agent.ErrRecoveryRequired
	}
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	if err = s.peerRecoveryIntegrity(ctx); err != nil {
		return false, err
	}
	var digest string
	var completed, superseded bool
	err = s.db.QueryRowContext(ctx, "SELECT approval_hash,completed,superseded FROM peer_recovery_approvals WHERE approval_id=?", value.Manifest.ApprovalId).Scan(&digest, &completed, &superseded)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, s.receiptReadFailure(ctx, err)
	}
	if digest != approved.Hash() || superseded {
		return false, agent.ErrConflict
	}
	if !completed {
		return false, nil
	}
	var obligations, reserved int
	if err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM executions WHERE state<>'cleaned' OR cleanup_pending=1 OR last_sequence<>ack_sequence").Scan(&obligations); err != nil {
		return false, s.receiptReadFailure(ctx, err)
	}
	if err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM reservations WHERE released=0").Scan(&reserved); err != nil {
		return false, s.receiptReadFailure(ctx, err)
	}
	if obligations != 0 || reserved != 0 {
		return false, agent.ErrRecoveryRequired
	}
	return true, nil
}
