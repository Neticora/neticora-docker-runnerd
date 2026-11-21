package journal

import (
	"context"
	"encoding/json"

	"github.com/Neticora/neticora-docker-runnerd/agent"
)

// VerifyActivationScope never creates a reconciliation checkpoint. Empty
// connection journals may activate for their original enrollment; settled
// history must match exactly. Changed boot/session/peer requires its existing
// independently authorized recovery path before activation can be retried.
func (s *SQLiteStore) VerifyActivationScope(ctx context.Context, scope agent.StoreScope) error {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	if !validScope(scope) || s.failed.Load() || s.anchorUncertain {
		return agent.ErrRecoveryRequired
	}
	if err = s.receiptIntegrity(ctx); err != nil {
		return err
	}
	if err = connectionSettled(ctx, s.db); err != nil {
		return err
	}
	var raw []byte
	if err = s.db.QueryRowContext(ctx, "SELECT scope FROM metadata WHERE singleton=1").Scan(&raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	var previous agent.StoreScope
	if json.Unmarshal(raw, &previous) != nil || previous != scope {
		return agent.ErrRecoveryRequired
	}
	return nil
}
