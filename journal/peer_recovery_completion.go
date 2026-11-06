package journal

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
)

// completionProgress permits finalization only for the exact applied approval,
// with no remaining obligations or physical reservations anywhere on the host.
// The returned counters are pinned by the completion intent before remote I/O.
func (s *SQLiteStore) completionProgress(ctx context.Context, reader recoveryReader, approved *peerrecovery.OperatorApproval) ([]byte, bool, error) {
	value, err := approved.Value()
	if err != nil {
		return nil, false, agent.ErrRecoveryRequired
	}
	plan := value.Manifest.Plan
	if plan.JournalId != s.anchor.JournalID {
		return nil, false, agent.ErrRecoveryRequired
	}
	var raw, scopeRaw []byte
	var digest string
	var completed, superseded bool
	if err = reader.QueryRowContext(ctx, "SELECT approval,approval_hash,completed,superseded FROM peer_recovery_approvals WHERE approval_id=?", value.Manifest.ApprovalId).Scan(&raw, &digest, &completed, &superseded); err != nil {
		return nil, false, err
	}
	canonical, err := peerrecovery.Canonical(value)
	if err != nil || digest != approved.Hash() || !bytes.Equal(raw, canonical) || superseded {
		return nil, false, agent.ErrConflict
	}
	if err = reader.QueryRowContext(ctx, "SELECT scope FROM metadata WHERE singleton=1").Scan(&scopeRaw); err != nil {
		return nil, false, err
	}
	var scope agent.StoreScope
	if json.Unmarshal(scopeRaw, &scope) != nil || scope != (agent.StoreScope{InstallationID: plan.InstallationId, TenantID: plan.Challenge.TenantId, HostID: plan.Challenge.Identity.HostId, SessionEpoch: plan.Challenge.Identity.SessionEpoch, EndpointIdentity: plan.TargetEndpointIdentity}) {
		return nil, false, agent.ErrRecoveryRequired
	}
	var obligations, reserved, cleanup int
	if err = reader.QueryRowContext(ctx, "SELECT count(*) FROM executions WHERE state<>'cleaned' OR cleanup_pending=1 OR last_sequence<>ack_sequence").Scan(&obligations); err != nil {
		return nil, false, err
	}
	if err = reader.QueryRowContext(ctx, "SELECT count(*) FROM reservations WHERE released=0").Scan(&reserved); err != nil {
		return nil, false, err
	}
	if err = reader.QueryRowContext(ctx, "SELECT count(*) FROM cleanup_tasks WHERE complete=0").Scan(&cleanup); err != nil {
		return nil, false, err
	}
	if obligations != 0 || reserved != 0 || cleanup != 0 {
		return nil, false, agent.ErrRecoveryRequired
	}
	for _, decision := range value.Manifest.Decisions {
		if decision.Action == "hold" {
			return nil, false, agent.ErrRecoveryRequired
		}
	}
	progress := make([]peerrecovery.NativeProgress, 0, len(plan.Executions))
	for _, execution := range plan.Executions {
		var last, ack, epoch, endpoint string
		var identityRaw []byte
		if err = reader.QueryRowContext(ctx, "SELECT last_sequence,ack_sequence,session_epoch,endpoint_identity,identity FROM executions WHERE execution_id=? AND generation=?", execution.ExecutionId, execution.Generation).Scan(&last, &ack, &epoch, &endpoint, &identityRaw); err != nil {
			return nil, false, err
		}
		var identity agent.Identity
		if json.Unmarshal(identityRaw, &identity) != nil || identity.InstallationID != plan.InstallationId || identity.TenantID != plan.Challenge.TenantId || identity.HostID != plan.Challenge.Identity.HostId || identity.ExecutionID != execution.ExecutionId || identity.Generation != execution.Generation || identity.SpecHash != execution.SpecHash || last != ack || padded(unpad(last)) != last || epoch != execution.OriginalSessionEpoch || endpoint != plan.SourceEndpointIdentity || last < padded(execution.LastSequence) {
			return nil, false, agent.ErrRecoveryRequired
		}
		progress = append(progress, peerrecovery.NativeProgress{ExecutionID: execution.ExecutionId, Generation: execution.Generation, LastSequence: unpad(last), AckSequence: unpad(ack)})
	}
	encoded, err := peerrecovery.Canonical(progress)
	return encoded, completed, err
}

// BeginPeerRecoveryCompletion anchors a completion-only intent before the
// platform can commit COMPLETED. No expiry exception can grant Docker authority.
func (s *SQLiteStore) BeginPeerRecoveryCompletion(ctx context.Context, approved *peerrecovery.OperatorApproval, checkpoint agent.RecoveryCheckpoint) error {
	if !fresh(checkpoint.ObservedAt) {
		return agent.ErrRecoveryRequired
	}
	return s.write(ctx, false, false, func(ctx context.Context, tx *sql.Tx) error {
		if checkpoint.Scope != s.scope || checkpoint.JournalID != s.anchor.JournalID || checkpoint.Revision != strconv.FormatInt(s.anchor.Revision, 10) || !fresh(checkpoint.ObservedAt) {
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
		progress, completed, err := s.completionProgress(ctx, tx, approved)
		if err != nil {
			return err
		}
		if completed {
			return agent.ErrConflict
		}
		value, err := approved.Value()
		if err != nil {
			return err
		}
		var digest string
		var saved []byte
		err = tx.QueryRowContext(ctx, "SELECT approval_hash,progress FROM peer_recovery_completion_intents WHERE approval_id=?", value.Manifest.ApprovalId).Scan(&digest, &saved)
		if err == nil {
			if digest != approved.Hash() || !bytes.Equal(saved, progress) {
				return agent.ErrConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO peer_recovery_completion_intents(approval_id,approval_hash,progress) VALUES(?,?,?)", value.Manifest.ApprovalId, approved.Hash(), progress)
		return err
	})
}

// PeerRecoveryCompletionReady uses protected local facts, never an expired file
// or caller-provided watermarks. A legacy applied grant with fully ACKed cleanup
// can establish its completion intent without reacquiring mutation permission.
func (s *SQLiteStore) PeerRecoveryCompletionReady(ctx context.Context, approved *peerrecovery.OperatorApproval) (bool, error) {
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
		return false, s.receiptReadFailure(ctx, err)
	}
	var digest string
	var saved []byte
	err = s.db.QueryRowContext(ctx, "SELECT approval_hash,progress FROM peer_recovery_completion_intents WHERE approval_id=?", value.Manifest.ApprovalId).Scan(&digest, &saved)
	if errors.Is(err, sql.ErrNoRows) {
		_, completed, err := s.completionProgress(ctx, s.db, approved)
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, agent.ErrRecoveryRequired) {
			return false, nil
		}
		return !completed && err == nil, err
	}
	if err != nil {
		return false, s.receiptReadFailure(ctx, err)
	}
	progress, completed, err := s.completionProgress(ctx, s.db, approved)
	if err != nil {
		return false, s.receiptReadFailure(ctx, err)
	}
	if digest != approved.Hash() || !bytes.Equal(saved, progress) {
		return false, agent.ErrConflict
	}
	return !completed, nil
}
