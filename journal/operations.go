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
)

type commandDocument struct {
	CommandID   string `json:"commandId"`
	PayloadHash string `json:"payloadHash"`
	Generation  string `json:"generation"`
	Kind        string `json:"kind"`
	ExecutionID string `json:"executionId"`
	Spec        struct {
		ExecutionID            string          `json:"executionId"`
		AttemptID              string          `json:"attemptId"`
		Generation             string          `json:"generation"`
		SpecHash               string          `json:"specHash"`
		PolicyGeneration       string          `json:"policyGeneration"`
		Resources              json.RawMessage `json:"resources"`
		AuthorizationExpiresAt time.Time       `json:"authorizationExpiresAt"`
	} `json:"spec"`
}

func snapshot(schema string, raw []byte, out any) ([]byte, error) {
	raw = bytes.Clone(raw)
	if err := protocol.ValidateInboundJSON(schema, raw); err != nil {
		return nil, agent.ErrConflict
	}
	canonical, err := protocol.CanonicalizeJSON(raw)
	if err != nil {
		return nil, agent.ErrConflict
	}
	if err = json.Unmarshal(canonical, out); err != nil {
		return nil, agent.ErrConflict
	}
	return canonical, nil
}

// AcceptCommand returns a receipt only after the command, exact immutable spec,
// and local reservation have committed and their revision anchor is synced.
// Exact durable replays use a read-only path independent of launch admission.
func (s *SQLiteStore) AcceptCommand(ctx context.Context, scope agent.StoreScope, raw json.RawMessage) (receipt agent.Receipt, err error) {
	return s.acceptCommand(ctx, scope, raw, true)
}

// Receipt recovers an exact durable duplicate without admitting new work. It
// shares the integrity, metadata and cancellation-safe read path with acceptance.
func (s *SQLiteStore) Receipt(ctx context.Context, scope agent.StoreScope, raw json.RawMessage) (agent.Receipt, error) {
	return s.acceptCommand(ctx, scope, raw, false)
}

func (s *SQLiteStore) acceptCommand(ctx context.Context, scope agent.StoreScope, raw json.RawMessage, allowNew bool) (receipt agent.Receipt, err error) {
	var doc commandDocument
	canonical, err := snapshot("HostCommand", raw, &doc)
	if err != nil {
		return receipt, err
	}
	if doc.Kind == "start" {
		doc.ExecutionID = doc.Spec.ExecutionID
		if doc.Generation != doc.Spec.Generation {
			return receipt, agent.ErrConflict
		}
	}
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return receipt, err
	}
	defer release()
	if s.failed.Load() {
		return receipt, agent.ErrStoreUnavailable
	}
	if s.anchorUncertain {
		return receipt, agent.ErrRecoveryRequired
	}
	if err = s.requireScope(scope); err != nil {
		return receipt, err
	}
	if err = s.receiptIntegrity(ctx); err != nil {
		return receipt, s.receiptReadFailure(ctx, err)
	}
	if s.fault != nil {
		if err = s.fault("receipt-lookup"); err != nil {
			return receipt, s.receiptReadFailure(ctx, err)
		}
	}
	var existing []byte
	var storedHash, storedExecution, storedGeneration, storedKind string
	err = s.db.QueryRowContext(ctx, "SELECT payload,payload_hash,execution_id,generation,kind FROM commands WHERE command_id=?", doc.CommandID).Scan(&existing, &storedHash, &storedExecution, &storedGeneration, &storedKind)
	if err == nil {
		if err = protocol.ValidateInboundJSON("HostCommand", existing); err != nil {
			s.failed.Store(true)
			return receipt, agent.ErrStoreUnavailable
		}
		var stored commandDocument
		if err = json.Unmarshal(existing, &stored); err != nil {
			s.failed.Store(true)
			return receipt, agent.ErrStoreUnavailable
		}
		execution := stored.ExecutionID
		if stored.Kind == "start" {
			execution = stored.Spec.ExecutionID
		}
		if stored.CommandID != doc.CommandID || stored.PayloadHash != storedHash || execution != storedExecution || stored.Generation != storedGeneration || stored.Kind != storedKind || (stored.Kind == "start" && stored.Generation != stored.Spec.Generation) {
			s.failed.Store(true)
			return receipt, agent.ErrStoreUnavailable
		}
		if !bytes.Equal(existing, canonical) {
			return receipt, agent.ErrConflict
		}
		return agent.Receipt{CommandID: doc.CommandID, PayloadHash: doc.PayloadHash, Generation: doc.Generation, Duplicate: true}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return receipt, s.receiptReadFailure(ctx, err)
	}
	if !allowNew {
		return receipt, agent.ErrNotFound
	}
	err = s.transactionOwned(ctx, doc.Kind == "start", doc.Kind == "start", false, func(ctx context.Context, tx *sql.Tx) error {
		if doc.Kind == "start" {
			if err := s.reserve(ctx, tx, doc.Spec.Resources); err != nil {
				return err
			}
			var oldGeneration string
			var state, lastSequence, ackSequence string
			var cleanupPending bool
			err = tx.QueryRowContext(ctx, "SELECT generation,state,cleanup_pending,last_sequence,ack_sequence FROM executions WHERE execution_id=? ORDER BY length(generation) DESC,generation DESC LIMIT 1", doc.ExecutionID).Scan(&oldGeneration, &state, &cleanupPending, &lastSequence, &ackSequence)
			if err == nil && (state != "cleaned" || cleanupPending || lastSequence != ackSequence || padded(oldGeneration) >= padded(doc.Generation)) {
				return agent.ErrConflict
			}
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			identity := agent.Identity{InstallationID: scope.InstallationID, TenantID: scope.TenantID, HostID: scope.HostID, ExecutionID: doc.ExecutionID, Generation: doc.Generation, SpecHash: doc.Spec.SpecHash, AttemptID: doc.Spec.AttemptID}
			identityRaw, _ := json.Marshal(identity)
			_, err = tx.ExecContext(ctx, "INSERT INTO executions(execution_id,generation,identity,session_epoch,endpoint_identity,attempt_id,command_id,command) VALUES(?,?,?,?,?,?,?,?)", doc.ExecutionID, doc.Generation, identityRaw, scope.SessionEpoch, scope.EndpointIdentity, doc.Spec.AttemptID, doc.CommandID, canonical)
			if err != nil {
				return sqlConflict(err)
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO reservations(execution_id,generation,resources) VALUES(?,?,?)", doc.ExecutionID, doc.Generation, []byte(doc.Spec.Resources)); err != nil {
				return err
			}
		} else {
			var count int
			if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM executions WHERE execution_id=? AND generation=?", doc.ExecutionID, doc.Generation).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				return agent.ErrNotFound
			}
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO commands(command_id,payload_hash,execution_id,generation,kind,payload) VALUES(?,?,?,?,?,?)", doc.CommandID, doc.PayloadHash, doc.ExecutionID, doc.Generation, doc.Kind, canonical); err != nil {
			return sqlConflict(err)
		}
		receipt = agent.Receipt{CommandID: doc.CommandID, PayloadHash: doc.PayloadHash, Generation: doc.Generation}
		return nil
	})
	if err != nil {
		return agent.Receipt{}, err
	}
	return receipt, nil
}

// An interrupted read establishes no journal failure. Only explicit context
// errors (or SQLite INTERRUPT tied to that context) avoid quarantine; a missing
// file, invalid row or revision mismatch still fails closed even if canceled.
func (s *SQLiteStore) receiptReadFailure(ctx context.Context, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var coded interface{ Code() int }
	if errors.As(err, &coded) && coded.Code()&255 == 9 && ctx.Err() != nil {
		return ctx.Err()
	}
	s.failed.Store(true)
	return agent.ErrStoreUnavailable
}

// Replay can bypass launch backpressure, never quarantine or installation
// integrity. Check both durable revisions without writing or advancing either.
func (s *SQLiteStore) receiptIntegrity(ctx context.Context) error {
	if err := s.checkFiles(); err != nil {
		return err
	}
	raw, err := hostfs.ReadPrivate(filepath.Join(s.dir, anchorName), 4096)
	if err != nil {
		return err
	}
	var disk anchor
	if err = json.Unmarshal(raw, &disk); err != nil || disk != s.anchor {
		return agent.ErrStoreUnavailable
	}
	var actual anchor
	if err = s.db.QueryRowContext(ctx, "SELECT journal_id,revision FROM metadata WHERE singleton=1").Scan(&actual.JournalID, &actual.Revision); err != nil {
		return err
	}
	if actual != s.anchor {
		return agent.ErrRecoveryRequired
	}
	return nil
}

// Constraint conflicts must not mask IO/FULL/CORRUPT failures.
func sqlConflict(err error) error {
	var coded interface{ Code() int }
	if errors.As(err, &coded) && coded.Code()&255 == 19 {
		return agent.ErrConflict
	}
	return err
}

func (s *SQLiteStore) PutStartIntent(ctx context.Context, scope agent.StoreScope, raw json.RawMessage) error {
	var doc struct {
		ExecutionID        string `json:"executionId"`
		Generation         string `json:"generation"`
		AttemptID          string `json:"attemptId"`
		CommandID          string `json:"commandId"`
		SpecHash           string `json:"specHash"`
		PolicyGeneration   string `json:"policyGeneration"`
		StartRequestID     string `json:"startRequestId"`
		BootstrapPublicKey string `json:"bootstrapPublicKey"`
	}
	canonical, err := snapshot("StartRequest", raw, &doc)
	if err != nil {
		return err
	}
	if doc.BootstrapPublicKey == "" {
		return agent.ErrConflict
	}
	return s.write(ctx, true, true, func(ctx context.Context, tx *sql.Tx) error {
		if err := s.requireScope(scope); err != nil {
			return err
		}
		var command []byte
		var epoch, endpoint, state string
		err := tx.QueryRowContext(ctx, "SELECT command,session_epoch,endpoint_identity,state FROM executions WHERE execution_id=? AND generation=?", doc.ExecutionID, doc.Generation).Scan(&command, &epoch, &endpoint, &state)
		if errors.Is(err, sql.ErrNoRows) {
			return agent.ErrNotFound
		}
		if err != nil {
			return err
		}
		var start commandDocument
		if err = json.Unmarshal(command, &start); err != nil {
			return err
		}
		if epoch != scope.SessionEpoch || endpoint != scope.EndpointIdentity || start.CommandID != doc.CommandID || start.Spec.SpecHash != doc.SpecHash || start.Spec.AttemptID != doc.AttemptID || start.Spec.PolicyGeneration != doc.PolicyGeneration {
			return agent.ErrConflict
		}
		var existing []byte
		err = tx.QueryRowContext(ctx, "SELECT request FROM start_intents WHERE execution_id=? AND generation=?", doc.ExecutionID, doc.Generation).Scan(&existing)
		if err == nil {
			if !bytes.Equal(existing, canonical) {
				return agent.ErrConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if state != "accepted" {
			return agent.ErrConflict
		}
		if !start.Spec.AuthorizationExpiresAt.After(time.Now()) {
			return agent.ErrConflict
		}
		var cancelled int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM commands WHERE execution_id=? AND generation=? AND kind IN ('cancel','cleanup','fence-never-started')", doc.ExecutionID, doc.Generation).Scan(&cancelled); err != nil {
			return err
		}
		if cancelled != 0 {
			return agent.ErrConflict
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO start_intents(execution_id,generation,start_request_id,request) VALUES(?,?,?,?)", doc.ExecutionID, doc.Generation, doc.StartRequestID, canonical)
		return sqlConflict(err)
	})
}

type eventDocument struct {
	NeverStarted json.RawMessage `json:"neverStarted"`
	EventID      string          `json:"eventId"`
	ExecutionID  string          `json:"executionId"`
	AttemptID    string          `json:"attemptId"`
	Generation   string          `json:"generation"`
	Sequence     string          `json:"sequence"`
	PayloadHash  string          `json:"payloadHash"`
	Observation  *struct {
		RuntimeRef json.RawMessage `json:"runtimeRef"`
		State      string          `json:"state"`
		ObservedAt time.Time       `json:"observedAt"`
	} `json:"observation"`
}

func (s *SQLiteStore) RecordObservation(ctx context.Context, scope agent.StoreScope, event json.RawMessage) error {
	return s.record(ctx, scope, event, "observe", agent.AbsenceEvidence{})
}
func (s *SQLiteStore) RequireCleanup(ctx context.Context, scope agent.StoreScope, event json.RawMessage) error {
	return s.record(ctx, scope, event, "cleanup", agent.AbsenceEvidence{})
}
func (s *SQLiteStore) CompleteCleanup(ctx context.Context, scope agent.StoreScope, event json.RawMessage, proof agent.AbsenceEvidence) error {
	return s.record(ctx, scope, event, "complete", proof)
}

// CompleteNeverStarted requires a matching permanent FENCED creation record and
// both durable server commands. It releases only an attempt that never crossed
// creation, together with its required outgoing signed proof.
func (s *SQLiteStore) CompleteNeverStarted(ctx context.Context, scope agent.StoreScope, event json.RawMessage) error {
	return s.record(ctx, scope, event, "never", agent.AbsenceEvidence{})
}

func (s *SQLiteStore) record(ctx context.Context, scope agent.StoreScope, raw json.RawMessage, operation string, proof agent.AbsenceEvidence) error {
	var doc eventDocument
	canonical, err := snapshot("HostEvent", raw, &doc)
	if err != nil {
		return err
	}
	if doc.Observation != nil {
		if doc.Observation.State == "cleaned" && operation != "complete" {
			return agent.ErrConflict
		}
		if doc.Observation.State == "cleanup-pending" && operation != "cleanup" {
			return agent.ErrConflict
		}
	}
	if operation == "never" && (doc.Observation != nil || len(doc.NeverStarted) == 0) {
		return agent.ErrConflict
	}
	if operation != "observe" && operation != "never" && (doc.Observation == nil || (operation == "cleanup" && doc.Observation.State != "cleanup-pending") || (operation == "complete" && doc.Observation.State != "cleaned")) {
		return agent.ErrConflict
	}
	return s.write(ctx, operation == "complete", false, func(ctx context.Context, tx *sql.Tx) error {
		if err := s.requireScope(scope); err != nil {
			return err
		}
		recovery, err := s.recoveryPermission(ctx, tx, doc.ExecutionID, doc.Generation)
		if err != nil {
			return err
		}
		if recovery != nil && (operation == "never" || recovery.Action == "replay-final-ack" || doc.Observation == nil || doc.Observation.State == "prepared" || doc.Observation.State == "running") {
			return agent.ErrRecoveryRequired
		}
		var existingHash, existingID string
		err = tx.QueryRowContext(ctx, "SELECT event_id,payload_hash FROM outbox_events WHERE execution_id=? AND generation=? AND sequence=?", doc.ExecutionID, doc.Generation, padded(doc.Sequence)).Scan(&existingID, &existingHash)
		if err == nil {
			if existingHash != doc.PayloadHash || existingID != doc.EventID {
				return agent.ErrConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var identityRaw, refRaw []byte
		var state, last, endpoint string
		var cleanup, terminal bool
		err = tx.QueryRowContext(ctx, "SELECT identity,state,runtime_ref,last_sequence,cleanup_pending,endpoint_identity,runtime_terminal FROM executions WHERE execution_id=? AND generation=?", doc.ExecutionID, doc.Generation).Scan(&identityRaw, &state, &refRaw, &last, &cleanup, &endpoint, &terminal)
		if errors.Is(err, sql.ErrNoRows) {
			return agent.ErrNotFound
		}
		if err != nil {
			return err
		}
		var id agent.Identity
		if err = json.Unmarshal(identityRaw, &id); err != nil {
			return err
		}
		seq, _ := strconv.ParseUint(doc.Sequence, 10, 64)
		previous, _ := strconv.ParseUint(last, 10, 64)
		if doc.AttemptID != id.AttemptID || previous == ^uint64(0) || seq != previous+1 {
			return agent.ErrConflict
		}
		if operation == "never" {
			if len(refRaw) != 0 || state != "accepted" || cleanup {
				return agent.ErrConflict
			}
			var proof map[string]string
			if json.Unmarshal(doc.NeverStarted, &proof) != nil {
				return agent.ErrConflict
			}
			if proof["tenantId"] != scope.TenantID || proof["hostId"] != scope.HostID || proof["executionId"] != id.ExecutionID || proof["generation"] != id.Generation || proof["attemptId"] != id.AttemptID || proof["specHash"] != id.SpecHash || proof["endpointIdentity"] != endpoint || proof["sessionEpoch"] != scope.SessionEpoch {
				return agent.ErrConflict
			}
			name, e := hash(map[string]string{"tenantId": scope.TenantID, "hostId": scope.HostID, "executionId": id.ExecutionID, "generation": id.Generation})
			if e != nil {
				return e
			}
			raw, e := hostfs.ReadPrivate(filepath.Join(s.dir, name+".creation.json"), 8192)
			if e != nil {
				return agent.ErrConflict
			}
			var marker record
			if json.Unmarshal(raw, &marker) != nil || marker.State != "FENCED" || marker.JournalID != proof["journalId"] || marker.FencedAt != proof["fencedAt"] {
				return agent.ErrConflict
			}
			for k, v := range marker.Binding {
				if proof[k] != v {
					return agent.ErrConflict
				}
			}
			var fenceRaw, startRaw []byte
			if e = tx.QueryRowContext(ctx, "SELECT payload FROM commands WHERE command_id=? AND execution_id=? AND generation=? AND kind='fence-never-started'", proof["fenceCommandId"], id.ExecutionID, id.Generation).Scan(&fenceRaw); e != nil {
				return agent.ErrConflict
			}
			if e = tx.QueryRowContext(ctx, "SELECT payload FROM commands WHERE command_id=? AND kind='start'", proof["startCommandId"]).Scan(&startRaw); e != nil {
				return agent.ErrConflict
			}
			var fence, start map[string]any
			if json.Unmarshal(fenceRaw, &fence) != nil || json.Unmarshal(startRaw, &start) != nil || fence["payloadHash"] != proof["fencePayloadHash"] || fence["challenge"] != proof["challenge"] || start["payloadHash"] != proof["startPayloadHash"] {
				return agent.ErrConflict
			}
			if _, e = tx.ExecContext(ctx, "UPDATE reservations SET released=1 WHERE execution_id=? AND generation=?", id.ExecutionID, id.Generation); e != nil {
				return e
			}
			state = "cleaned"
			terminal = true
		}
		if doc.Observation != nil {
			if terminal && (doc.Observation.State == "running" || doc.Observation.State == "prepared") {
				return agent.ErrConflict
			}
			var ref struct {
				ExecutionID string `json:"executionId"`
				Generation  string `json:"generation"`
				SpecHash    string `json:"specHash"`
				Scope       string `json:"scope"`
			}
			if err = json.Unmarshal(doc.Observation.RuntimeRef, &ref); err != nil {
				return err
			}
			if ref.ExecutionID != id.ExecutionID || ref.Generation != id.Generation || ref.SpecHash != id.SpecHash || ref.Scope != endpoint {
				return agent.ErrConflict
			}
			if len(refRaw) > 0 && !bytes.Equal(refRaw, doc.Observation.RuntimeRef) {
				return agent.ErrConflict
			}
			if state == "cleaned" || (cleanup && operation == "observe" && doc.Observation.State != "unknown") || (state == "exited" && (doc.Observation.State == "running" || doc.Observation.State == "prepared")) || (state == "running" && doc.Observation.State == "prepared") {
				return agent.ErrConflict
			}
			if operation == "complete" {
				var known bool
				var inventory string
				if err = tx.QueryRowContext(ctx, "SELECT runtime_known,inventory_generation FROM metadata WHERE singleton=1").Scan(&known, &inventory); err != nil {
					return err
				}
				proofRef, e := protocol.CanonicalizeJSON(proof.RuntimeRef)
				if e != nil || !bytes.Equal(proofRef, doc.Observation.RuntimeRef) || !known || !cleanup || (recovery == nil && endpoint != scope.EndpointIdentity) || proof.EndpointIdentity != scope.EndpointIdentity || !validCounter(proof.InventoryGeneration, false) || padded(proof.InventoryGeneration) < padded(inventory) || !fresh(proof.ObservedAt) || doc.Observation.ObservedAt.Before(proof.ObservedAt) {
					return agent.ErrRecoveryRequired
				}
				proofRaw, _ := json.Marshal(proof)
				if _, err = tx.ExecContext(ctx, "UPDATE cleanup_tasks SET complete=1,evidence=? WHERE execution_id=? AND generation=?", proofRaw, doc.ExecutionID, doc.Generation); err != nil {
					return err
				}
				if _, err = tx.ExecContext(ctx, "UPDATE reservations SET released=1 WHERE execution_id=? AND generation=?", doc.ExecutionID, doc.Generation); err != nil {
					return err
				}
				if _, err = tx.ExecContext(ctx, "UPDATE metadata SET inventory_generation=?,inventory_observed_at=? WHERE singleton=1", proof.InventoryGeneration, proof.ObservedAt.UTC().Format(time.RFC3339Nano)); err != nil {
					return err
				}
				cleanup = false
			}
			if operation == "cleanup" {
				cleanup = true
				if _, err = tx.ExecContext(ctx, "INSERT INTO cleanup_tasks(execution_id,generation) VALUES(?,?) ON CONFLICT(execution_id,generation) DO NOTHING", doc.ExecutionID, doc.Generation); err != nil {
					return err
				}
			}
			state = doc.Observation.State
			terminal = terminal || state == "exited" || state == "cleaned"
			refRaw = doc.Observation.RuntimeRef
		}
		var count int
		var size int64
		if err = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(length(payload)),0) FROM outbox_events WHERE payload IS NOT NULL").Scan(&count, &size); err != nil {
			return err
		}
		if count >= s.options.MaxOutboxEvents || int64(len(canonical)) > s.options.MaxOutboxBytes-size {
			// Mandatory cleanup facts obey the same hard bound. Roll back the
			// entire obligation/completion, retain resources and retry after ACK;
			// no destructive runtime action may follow this error.
			return agent.ErrCapacity
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO outbox_events(execution_id,generation,sequence,event_id,payload_hash,payload) VALUES(?,?,?,?,?,?)", doc.ExecutionID, doc.Generation, padded(doc.Sequence), doc.EventID, doc.PayloadHash, canonical); err != nil {
			return sqlConflict(err)
		}
		if s.fault != nil {
			if err = s.fault("after-event"); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, "UPDATE executions SET state=?,runtime_ref=?,cleanup_pending=?,last_sequence=?,runtime_terminal=? WHERE execution_id=? AND generation=?", state, refRaw, cleanup, padded(doc.Sequence), terminal, doc.ExecutionID, doc.Generation)
		return err
	})
}

func fresh(t time.Time) bool {
	return !t.IsZero() && !t.After(time.Now().Add(5*time.Second)) && time.Since(t) < time.Minute
}

func ack(ctx context.Context, tx *sql.Tx, w agent.Watermark) error {
	if !validCounter(w.Generation, false) || !validCounter(w.ContiguousSequence, true) {
		return agent.ErrConflict
	}
	var last, committed string
	err := tx.QueryRowContext(ctx, "SELECT last_sequence,ack_sequence FROM executions WHERE execution_id=? AND generation=?", w.ExecutionID, w.Generation).Scan(&last, &committed)
	if errors.Is(err, sql.ErrNoRows) {
		return agent.ErrNotFound
	}
	if err != nil {
		return err
	}
	next := padded(w.ContiguousSequence)
	if next > last {
		return agent.ErrConflict
	}
	if next <= committed {
		return nil
	}
	// Sequence rows are retained as compact identity/hash tombstones. Check the
	// full contiguous interval before dropping acknowledged payload bytes.
	var count int64
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM outbox_events WHERE execution_id=? AND generation=? AND sequence>? AND sequence<=?", w.ExecutionID, w.Generation, committed, next).Scan(&count); err != nil {
		return err
	}
	a, _ := strconv.ParseUint(committed, 10, 64)
	b, _ := strconv.ParseUint(next, 10, 64)
	if uint64(count) != b-a {
		return agent.ErrConflict
	}
	if _, err = tx.ExecContext(ctx, "UPDATE outbox_events SET payload=NULL WHERE execution_id=? AND generation=? AND sequence<=?", w.ExecutionID, w.Generation, next); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE executions SET ack_sequence=? WHERE execution_id=? AND generation=?", next, w.ExecutionID, w.Generation)
	return err
}

func (s *SQLiteStore) AckEvents(ctx context.Context, scope agent.StoreScope, w agent.Watermark) error {
	return s.write(ctx, false, false, func(ctx context.Context, tx *sql.Tx) error {
		if err := s.requireScope(scope); err != nil {
			return err
		}
		return ack(ctx, tx, w)
	})
}

func (s *SQLiteStore) Reconcile(ctx context.Context, c agent.RecoveryCheckpoint) error {
	runtimeGeneration := s.runtimeGeneration.Load()
	if !validScope(c.Scope) || !validCounter(c.InventoryGeneration, false) || !fresh(c.ObservedAt) {
		return agent.ErrRecoveryRequired
	}
	err := s.transaction(ctx, false, false, true, func(ctx context.Context, tx *sql.Tx) error {
		if c.JournalID != s.anchor.JournalID || c.Revision != strconv.FormatInt(s.anchor.Revision, 10) {
			return agent.ErrRecoveryRequired
		}
		if s.restoredEpoch != "" && padded(c.Scope.SessionEpoch) <= padded(s.restoredEpoch) {
			return agent.ErrRecoveryRequired
		}
		var oldRaw []byte
		var generation string
		if err := tx.QueryRowContext(ctx, "SELECT scope,inventory_generation FROM metadata WHERE singleton=1").Scan(&oldRaw, &generation); err != nil {
			return err
		}
		if len(oldRaw) > 0 {
			var old agent.StoreScope
			if err := json.Unmarshal(oldRaw, &old); err != nil {
				return err
			}
			if old.InstallationID != c.Scope.InstallationID || old.TenantID != c.Scope.TenantID || old.HostID != c.Scope.HostID || padded(old.SessionEpoch) > padded(c.Scope.SessionEpoch) {
				return agent.ErrConflict
			}
			if old.EndpointIdentity == c.Scope.EndpointIdentity && padded(c.InventoryGeneration) <= padded(generation) {
				return agent.ErrRecoveryRequired
			}
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM executions WHERE state<>'cleaned' OR cleanup_pending=1 OR last_sequence>ack_sequence").Scan(&count); err != nil {
			return err
		}
		covered := 0
		seen := make(map[agent.ExecutionCursor]bool)
		for _, w := range c.ServerWatermarks {
			key := agent.ExecutionCursor{ExecutionID: w.ExecutionID, Generation: w.Generation}
			if seen[key] {
				return agent.ErrConflict
			}
			seen[key] = true
			var committed, state, last string
			var cleanup bool
			if err := tx.QueryRowContext(ctx, "SELECT ack_sequence,state,last_sequence,cleanup_pending FROM executions WHERE execution_id=? AND generation=?", w.ExecutionID, w.Generation).Scan(&committed, &state, &last, &cleanup); err != nil {
				return agent.ErrRecoveryRequired
			}
			if !validCounter(w.ContiguousSequence, true) || padded(w.ContiguousSequence) < committed {
				return agent.ErrRecoveryRequired
			}
			if state != "cleaned" || cleanup || last > committed {
				covered++
			}
			if err := ack(ctx, tx, w); err != nil {
				return err
			}
		}
		if covered != count {
			return agent.ErrRecoveryRequired
		}
		raw, _ := json.Marshal(c.Scope)
		_, err := tx.ExecContext(ctx, "UPDATE metadata SET scope=?,inventory_generation=?,inventory_observed_at=?,runtime_known=1 WHERE singleton=1", raw, c.InventoryGeneration, c.ObservedAt.UTC().Format(time.RFC3339Nano))
		return err
	}, func() {
		s.scope = c.Scope
		s.ready = true
		s.sessionReady = true
		s.reconciledGeneration = runtimeGeneration
		s.inventoryObservedAt = c.ObservedAt
	})
	return err
}

func (s *SQLiteStore) InvalidateRuntime(ctx context.Context) error {
	s.runtimeGeneration.Add(1)
	// Disable in memory even when the durable write cannot complete.
	_, release, err := s.acquire(ctx)
	if err != nil {
		s.failed.Store(true)
		return err
	}
	s.ready = false
	release()
	err = s.write(ctx, false, false, func(ctx context.Context, tx *sql.Tx) error {
		s.ready = false
		_, err := tx.ExecContext(ctx, "UPDATE metadata SET runtime_known=0 WHERE singleton=1")
		return err
	})
	if err != nil {
		s.failed.Store(true)
	}
	return err
}
