package journal

import (
	"context"
	"encoding/json"

	"github.com/Neticora/neticora-docker-runnerd/agent"
)

// SetReservationLimits activates trusted host-local ceilings before subsequent
// admission/creation checks. It never releases existing reservations.
func (s *SQLiteStore) SetReservationLimits(ctx context.Context, limits agent.ReservationLimits) error {
	_, release, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	s.options.ReservationLimits = limits
	return nil
}

// ControlCommands retains accepted cancellation/fence intent across daemon
// restart. It is bounded and does not expose SQL to runtime/provider adapters.
func (s *SQLiteStore) ControlCommands(ctx context.Context, id, generation string) ([]json.RawMessage, error) {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if s.failed.Load() || !s.sessionReady {
		return nil, agent.ErrRecoveryRequired
	}
	rows, err := s.db.QueryContext(ctx, "SELECT payload FROM commands WHERE execution_id=? AND generation=? AND kind<>'start' ORDER BY command_id LIMIT 101", id, generation)
	if err != nil {
		return nil, agent.ErrStoreUnavailable
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var raw json.RawMessage
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	if len(out) > 100 {
		return nil, agent.ErrCapacity
	}
	return out, rows.Err()
}

func (s *SQLiteStore) PendingEvents(ctx context.Context, page agent.EventPage) ([]json.RawMessage, error) {
	return s.pendingEvents(ctx, page, true)
}

func (s *SQLiteStore) pendingEvents(ctx context.Context, page agent.EventPage, requireSession bool) ([]json.RawMessage, error) {
	if page.Limit < 1 || page.Limit > 100 || !validID(page.ExecutionID) || !validCounter(page.Generation, false) || !validCounter(page.AfterSequence, true) {
		return nil, agent.ErrConflict
	}
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if requireSession && !s.sessionReady {
		return nil, agent.ErrRecoveryRequired
	}
	if s.failed.Load() {
		return nil, agent.ErrStoreUnavailable
	}
	rows, err := s.db.QueryContext(ctx, "SELECT payload FROM outbox_events WHERE execution_id=? AND generation=? AND sequence>? AND payload IS NOT NULL ORDER BY sequence LIMIT ?", page.ExecutionID, page.Generation, padded(page.AfterSequence), page.Limit)
	if err != nil {
		return nil, agent.ErrStoreUnavailable
	}
	defer rows.Close()
	out := make([]json.RawMessage, 0)
	for rows.Next() {
		var raw json.RawMessage
		if err = rows.Scan(&raw); err != nil {
			return nil, agent.ErrStoreUnavailable
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}

// Incomplete remains available before reconciliation for read-only diagnosis.
// It retains cleaned executions until their final outgoing facts are ACKed.
func (s *SQLiteStore) Incomplete(ctx context.Context, after agent.ExecutionCursor, limit int) ([]agent.Execution, error) {
	return s.executions(ctx, after, limit, false)
}

func (s *SQLiteStore) Executions(ctx context.Context, after agent.ExecutionCursor, limit int) ([]agent.Execution, error) {
	return s.executions(ctx, after, limit, true)
}

func (s *SQLiteStore) executions(ctx context.Context, after agent.ExecutionCursor, limit int, all bool) ([]agent.Execution, error) {
	if limit < 1 || limit > 100 {
		return nil, agent.ErrConflict
	}
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	rows, err := s.db.QueryContext(ctx, `SELECT e.identity,e.command_id,e.command,i.request,e.state,e.runtime_ref,e.cleanup_pending,e.last_sequence,e.ack_sequence
	  FROM executions e LEFT JOIN start_intents i USING(execution_id,generation)
	  WHERE (? OR e.state<>'cleaned' OR e.cleanup_pending=1 OR e.last_sequence>e.ack_sequence)
	  AND (e.execution_id>? OR (e.execution_id=? AND e.generation>?))
	  ORDER BY e.execution_id,e.generation LIMIT ?`, all, after.ExecutionID, after.ExecutionID, after.Generation, limit)
	if err != nil {
		return nil, agent.ErrStoreUnavailable
	}
	defer rows.Close()
	out := make([]agent.Execution, 0)
	for rows.Next() {
		var e agent.Execution
		var identity, command, request, ref []byte
		if err = rows.Scan(&identity, &e.CommandID, &command, &request, &e.State, &ref, &e.CleanupPending, &e.LastSequence, &e.AckSequence); err != nil {
			return nil, agent.ErrStoreUnavailable
		}
		e.Command = command
		e.StartRequest = request
		e.RuntimeRef = ref
		if err = json.Unmarshal(identity, &e.Identity); err != nil {
			return nil, agent.ErrStoreUnavailable
		}
		e.LastSequence = unpad(e.LastSequence)
		e.AckSequence = unpad(e.AckSequence)
		out = append(out, e)
	}
	return out, rows.Err()
}
