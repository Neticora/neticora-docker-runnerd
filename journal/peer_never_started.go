package journal

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
)

// ExistingNeverStartedFence is read-only and uses the original execution
// identity. Absence of a marker, launch intent or runtime is never inferred
// from the replacement peer's Docker inventory.
func (s *SQLiteStore) ExistingNeverStartedFence(ctx context.Context, cursor agent.ExecutionCursor, a Authority) error {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	_, _, err = s.existingNeverStartedFence(ctx, cursor, a)
	return err
}

func (s *SQLiteStore) existingNeverStartedFence(ctx context.Context, cursor agent.ExecutionCursor, a Authority) (start, fence []byte, err error) {
	if s.checkFiles() != nil || s.peerRecoveryIntegrity(ctx) != nil {
		return nil, nil, agent.ErrRecoveryRequired
	}
	err = s.db.QueryRowContext(ctx, `
SELECT e.command, f.payload
FROM executions e JOIN commands f USING (execution_id,generation)
WHERE e.execution_id=? AND e.generation=? AND f.kind='fence-never-started'
AND e.session_epoch=? AND e.endpoint_identity=? AND e.state='accepted'
AND e.runtime_ref IS NULL AND e.cleanup_pending=0 AND e.last_sequence='00000000000000000000'
AND NOT EXISTS(SELECT 1 FROM start_intents i WHERE i.execution_id=e.execution_id AND i.generation=e.generation)
AND NOT EXISTS(SELECT 1 FROM kata_cache_volumes v WHERE v.execution_id=e.execution_id AND v.generation=e.generation)`,
		cursor.ExecutionID, cursor.Generation, a.SessionEpoch, a.EndpointIdentity).Scan(&start, &fence)
	if err != nil {
		return nil, nil, err
	}
	startDoc, err := decode("StartCommand", start)
	if err != nil {
		return nil, nil, err
	}
	expected, err := binding(startDoc, a)
	if err != nil || expected["executionId"] != cursor.ExecutionID || expected["generation"] != cursor.Generation {
		return nil, nil, agent.ErrConflict
	}
	id, err := hash(map[string]string{"tenantId": a.TenantID, "hostId": a.HostID, "executionId": cursor.ExecutionID, "generation": cursor.Generation})
	if err != nil {
		return nil, nil, err
	}
	raw, err := hostfs.ReadPrivate(filepath.Join(s.dir, id+".creation.json"), 8192)
	var proof record
	if err != nil || json.Unmarshal(raw, &proof) != nil || proof.State != "FENCED" || proof.JournalID == "" || proof.FencedAt == "" {
		return nil, nil, agent.ErrConflict
	}
	actualHash, _ := hash(proof.Binding)
	expectedHash, _ := hash(expected)
	if actualHash != expectedHash {
		return nil, nil, agent.ErrConflict
	}
	return start, fence, nil
}

// AttestPeerNeverStarted re-signs an existing original fence under a fresh
// committed cleanup-only peer approval. It grants no resource mutation.
func (s *SQLiteStore) AttestPeerNeverStarted(ctx context.Context, approval *peerrecovery.Authorization, cursor agent.ExecutionCursor, a Authority, key ed25519.PrivateKey) ([]byte, error) {
	if !approval.Current(time.Now()) {
		return nil, agent.ErrRecoveryRequired
	}
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	decision, err := s.recoveryPermission(ctx, s.db, cursor.ExecutionID, cursor.Generation)
	if err != nil || decision == nil || decision.Action != "verify-never-started" {
		return nil, agent.ErrRecoveryRequired
	}
	var digest string
	err = s.db.QueryRowContext(ctx, "SELECT approval_hash FROM peer_recovery_approvals WHERE completed=0 AND superseded=0").Scan(&digest)
	if err != nil || digest != approval.Approval().Hash() || a.TenantID != s.scope.TenantID || a.HostID != s.scope.HostID {
		return nil, agent.ErrRecoveryRequired
	}
	start, fence, err := s.existingNeverStartedFence(ctx, cursor, a)
	if err != nil {
		return nil, err
	}
	return s.fences.FenceNeverStarted(start, fence, a, key, time.Now())
}
