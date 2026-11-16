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

// Connection-only recovery refuses ANY execution history or established execution
// scope. Such installations must use the existing signed execution peer recovery.
// This method cannot reconcile a journal or establish execution readiness.
func connectionEmpty(ctx context.Context, q recoveryReader) error {
	for _, table := range []string{"executions", "commands", "reservations", "start_intents", "outbox_events", "cleanup_tasks", "execution_storage", "peer_recovery_approvals", "peer_recovery_completion_intents"} {
		var n int
		if err := q.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			return agent.ErrRecoveryRequired
		}
	}
	var scope []byte
	if err := q.QueryRowContext(ctx, "SELECT scope FROM metadata WHERE singleton=1").Scan(&scope); err != nil {
		return err
	}
	if len(scope) != 0 {
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
	if err = connectionEmpty(ctx, s.db); err != nil {
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
		if err := connectionEmpty(ctx, tx); err != nil {
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
		if err := connectionEmpty(ctx, tx); err != nil {
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
