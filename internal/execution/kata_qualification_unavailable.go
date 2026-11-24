//go:build !linux || !runnerd_qualification

package execution

import (
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

func openConfiguredQualification(config.Config, *journal.SQLiteStore, *PolicyFile, func() bool) (*Controller, func(), error) {
	return nil, nil, ErrReconcile
}

func loadStandalonePeerRecovery(config.Config, Credentials) (*katalinux.Profile, *kataCache, error) {
	return nil, nil, ErrReconcile
}
