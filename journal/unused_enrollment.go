package journal

import (
	"context"
	"github.com/Neticora/neticora-docker-runnerd/agent"
)

// UnusedEnrollment refuses even completed history and any previous native
// runtime binding. It is not a cleanup or recovery certificate.
func (s *SQLiteStore) UnusedEnrollment(ctx context.Context) error {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	if s.failed.Load() {
		return agent.ErrStoreUnavailable
	}
	if err = s.peerRecoveryIntegrity(ctx); err != nil {
		return err
	}
	var count int
	err = s.db.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM executions)+(SELECT count(*) FROM commands)+
 (SELECT count(*) FROM reservations)+(SELECT count(*) FROM start_intents)+
 (SELECT count(*) FROM outbox_events)+(SELECT count(*) FROM cleanup_tasks)+
 (SELECT count(*) FROM peer_recovery_approvals)+
 (SELECT count(*) FROM metadata WHERE scope IS NOT NULL OR runtime_known<>0 OR inventory_generation<>'0')`).Scan(&count)
	if err != nil {
		return err
	}
	if count != 0 {
		return agent.ErrRecoveryRequired
	}
	return nil
}
