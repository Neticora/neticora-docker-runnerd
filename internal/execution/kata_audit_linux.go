//go:build linux && runnerd_qualification

package execution

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

// AuditClosedQualificationJournal takes the native exclusive journal lock and
// validates existing durable history. It never creates a journal, changes its
// scope/identity or declares qualification. It is available only to lab builds.
func AuditClosedQualificationJournal(ctx context.Context, file string) (map[string]any, error) {
	if os.Geteuid() == 0 || os.Getenv("RUNNERD09_LIVE_QUALIFICATION") != "1" {
		return nil, ErrReconcile
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		return nil, err
	}
	raw, err := hostfs.ReadPrivate(file, config.MaxConfigBytes)
	if err != nil {
		return nil, err
	}
	c, err := config.Parse(raw)
	if err != nil {
		return nil, err
	}
	credentials, key, err := ReadCredentials(c.CredentialFile)
	clear(key)
	if err != nil || !strings.HasPrefix(credentials.InstallationID, "runnerd09-lab-") || credentials.InstallationID != credentials.Identity.HostId || credentials.InstallationID != credentials.TenantID {
		return nil, ErrReconcile
	}
	boot, err := actualBootID()
	if err != nil || boot != credentials.BootID {
		return nil, ErrReconcile
	}
	// Refuse a missing database before OpenRecovery can initialize anything.
	if _, err = os.Lstat(filepath.Join(c.StateDir, "journal.db")); err != nil {
		return nil, err
	}
	store, err := journal.OpenRecovery(ctx, c.StateDir, journal.Options{})
	if err != nil {
		return nil, err
	}
	defer store.Close()
	scope, err := store.PeerRecoveryScope(ctx)
	if err != nil || scope.InstallationID != credentials.InstallationID || scope.HostID != credentials.Identity.HostId || scope.TenantID != credentials.TenantID || scope.EndpointIdentity != credentials.EndpointIdentity || scope.SessionEpoch != credentials.Identity.SessionEpoch {
		return nil, ErrReconcile
	}
	cursor := agent.ExecutionCursor{}
	count := 0
	for {
		rows, err := store.Executions(ctx, cursor, 100)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if row.State != "cleaned" || row.CleanupPending || row.LastSequence != row.AckSequence || row.Identity.InstallationID != scope.InstallationID || row.Identity.HostID != scope.HostID || row.Identity.TenantID != scope.TenantID {
				return nil, ErrReconcile
			}
			count++
			if count > 10000 {
				return nil, ErrReconcile
			}
			cursor = agent.ExecutionCursor{ExecutionID: row.Identity.ExecutionID, Generation: row.Identity.Generation}
		}
		if len(rows) < 100 {
			break
		}
	}
	health := store.Health(ctx)
	raw, _ = json.Marshal(health)
	return map[string]any{"version": "runnerd09-closed-journal-v1", "closed": true, "executions": count, "hostId": scope.HostID, "bootId": boot, "journal": json.RawMessage(raw), "productionAdmission": false}, nil
}
