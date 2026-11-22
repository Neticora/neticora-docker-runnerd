package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
)

type ConnectionRecovery struct {
	Intent    protocol.ConnectionResyncIntent
	Receipt   *protocol.ConnectionResyncResponse
	Completed bool
}

// Completed immutable history is retained. Only unresolved obligations block
// observation recovery; metadata scope and historical resource identities remain
// unchanged and are never used as a new execution checkpoint.
func connectionSettled(ctx context.Context, q recoveryReader) error {
	checks := []string{
		"SELECT EXISTS(SELECT 1 FROM executions WHERE json_valid(identity)=0 OR json_valid(command)=0)",
		"SELECT EXISTS(SELECT 1 FROM executions WHERE state<>'cleaned' OR runtime_terminal<>1 OR cleanup_pending<>0 OR last_sequence<>ack_sequence)",
		"SELECT EXISTS(SELECT 1 FROM reservations WHERE released<>1)",
		"SELECT EXISTS(SELECT 1 FROM outbox_events o JOIN executions e USING(execution_id,generation) WHERE o.sequence>e.ack_sequence OR o.payload IS NOT NULL)",
		"SELECT EXISTS(SELECT 1 FROM cleanup_tasks WHERE complete<>1 OR evidence IS NULL OR json_valid(evidence)=0)",
		"SELECT EXISTS(SELECT 1 FROM execution_storage WHERE state<>'disposed' OR json_valid(record)=0)",
		"SELECT EXISTS(SELECT 1 FROM peer_recovery_approvals WHERE completed=0 AND superseded=0)",
		"SELECT EXISTS(SELECT 1 FROM peer_recovery_completion_intents i JOIN peer_recovery_approvals a USING(approval_id) WHERE a.completed=0 AND a.superseded=0)",
	}
	for _, query := range checks {
		var unresolved bool
		if err := q.QueryRowContext(ctx, query).Scan(&unresolved); err != nil {
			return err
		}
		if unresolved {
			return agent.ErrRecoveryRequired
		}
	}
	var raw []byte
	var history bool
	if err := q.QueryRowContext(ctx, "SELECT scope,EXISTS(SELECT 1 FROM executions) FROM metadata WHERE singleton=1").Scan(&raw, &history); err != nil {
		return err
	}
	if len(raw) == 0 {
		if history {
			return agent.ErrRecoveryRequired
		}
		return nil
	}
	var scope agent.StoreScope
	if json.Unmarshal(raw, &scope) != nil || !validScope(scope) {
		return agent.ErrRecoveryRequired
	}
	return nil
}
func connectionHistoryBinding(ctx context.Context, q recoveryReader, intent protocol.ConnectionResyncIntent) error {
	var raw []byte
	if err := q.QueryRowContext(ctx, "SELECT scope FROM metadata WHERE singleton=1").Scan(&raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	var scope agent.StoreScope
	if json.Unmarshal(raw, &scope) != nil || scope.InstallationID != intent.InstallationId || scope.TenantID != intent.TenantId || scope.HostID != intent.Identity.HostId || padded(scope.SessionEpoch) > padded(intent.Identity.SessionEpoch) {
		return agent.ErrRecoveryRequired
	}
	return nil
}

func (s *SQLiteStore) ConnectionRecovery(ctx context.Context) (*ConnectionRecovery, error) {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if s.failed.Load() || s.checkFiles() != nil {
		return nil, agent.ErrStoreUnavailable
	}
	if !s.anchorUncertain {
		if err = s.receiptIntegrity(ctx); err != nil {
			return nil, err
		}
	}
	rows, e := s.db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if e != nil {
		return nil, e
	}
	violation := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return nil, rowErr
	}
	if violation {
		return nil, agent.ErrRecoveryRequired
	}
	if err = connectionSettled(ctx, s.db); err != nil {
		return nil, err
	}
	var raw, response []byte
	var storedHash string
	var completed bool
	var revision int64
	err = s.db.QueryRowContext(ctx, "SELECT request,request_hash,response,completed,write_revision FROM connection_resync ORDER BY write_revision DESC LIMIT 1").Scan(&raw, &storedHash, &response, &completed, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		if s.anchorUncertain {
			return nil, agent.ErrRecoveryRequired
		}
		return nil, nil
	}
	if err != nil {
		return nil, agent.ErrStoreUnavailable
	}
	var intent protocol.ConnectionResyncIntent
	if protocol.ValidateInboundJSON("ConnectionResyncIntent", raw) != nil || json.Unmarshal(raw, &intent) != nil {
		return nil, agent.ErrRecoveryRequired
	}
	h, e := peerrecovery.Hash(intent)
	if e != nil || h != storedHash || intent.JournalId != s.anchor.JournalID || revision > s.anchor.Revision || (s.anchorUncertain && revision != s.anchor.Revision) {
		return nil, agent.ErrRecoveryRequired
	}
	result := &ConnectionRecovery{Intent: intent, Completed: completed}
	if len(response) > 0 {
		var receipt protocol.ConnectionResyncResponse
		if protocol.ValidateInboundJSON("ConnectionResyncResponse", response) != nil || json.Unmarshal(response, &receipt) != nil || receipt.RequestHash != h || receipt.OperationId != intent.OperationId || receipt.State != "committed" {
			return nil, agent.ErrRecoveryRequired
		}
		result.Receipt = &receipt
	}
	if completed && result.Receipt == nil {
		return nil, agent.ErrRecoveryRequired
	}
	historyIntent := intent
	if completed && result.Receipt != nil {
		historyIntent.Identity = result.Receipt.Identity
	}
	if err = connectionHistoryBinding(ctx, s.db, historyIntent); err != nil {
		return nil, err
	}
	return result, nil
}

// BeginConnectionRecovery durably commits the one exact operation before any HTTP
// request. The original installation lock serializes daemon/recovery processes.
func (s *SQLiteStore) BeginConnectionRecovery(ctx context.Context, intent protocol.ConnectionResyncIntent) error {
	raw, err := protocol.EncodeValidated("ConnectionResyncIntent", intent)
	if err != nil {
		return err
	}
	h, err := peerrecovery.Hash(intent)
	if err != nil {
		return err
	}
	return s.transaction(ctx, false, false, false, func(ctx context.Context, tx *sql.Tx) error {
		if err := connectionSettled(ctx, tx); err != nil {
			return err
		}
		if err := connectionHistoryBinding(ctx, tx, intent); err != nil {
			return err
		}
		if intent.JournalId != s.anchor.JournalID || intent.JournalRevision != strconv.FormatInt(s.anchor.Revision, 10) {
			return agent.ErrConflict
		}
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM connection_resync WHERE completed=0").Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			return agent.ErrConflict
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO connection_resync(operation_id,request,request_hash,write_revision) VALUES(?,?,?,?)", intent.OperationId, raw.Bytes(), h, s.anchor.Revision+1)
		return err
	})
}

// RecordConnectionRecovery may repair an interrupted anchor only for this exact
// durable operation after an authenticated server response. It never sets scope,
// runtime_known, sessionReady or inventory checkpoints.
func (s *SQLiteStore) RecordConnectionRecovery(ctx context.Context, intent protocol.ConnectionResyncIntent, receipt protocol.ConnectionResyncResponse, complete bool) error {
	prior, err := s.ConnectionRecovery(ctx)
	if err != nil || prior == nil {
		return agent.ErrRecoveryRequired
	}
	h, err := peerrecovery.Hash(intent)
	if err != nil {
		return err
	}
	old, _ := peerrecovery.Hash(prior.Intent)
	if old != h || receipt.RequestHash != h || receipt.OperationId != intent.OperationId || receipt.State != "committed" {
		return agent.ErrConflict
	}
	raw, err := protocol.EncodeValidated("ConnectionResyncResponse", receipt)
	if err != nil {
		return err
	}
	return s.transaction(ctx, false, false, true, func(ctx context.Context, tx *sql.Tx) error {
		if err := connectionSettled(ctx, tx); err != nil {
			return err
		}
		if prior.Receipt != nil {
			a, _ := peerrecovery.Hash(*prior.Receipt)
			b, _ := peerrecovery.Hash(receipt)
			if a != b {
				return agent.ErrConflict
			}
		}
		_, err := tx.ExecContext(ctx, "UPDATE connection_resync SET response=?,completed=?,write_revision=? WHERE operation_id=? AND request_hash=?", raw.Bytes(), complete, s.anchor.Revision+1, intent.OperationId, h)
		return err
	})
}
