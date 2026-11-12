//go:build linux && !runnerd_qualification

package broker

import (
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

func loadKata(c Config, x KataConfig, base standardlinux.Settings) (*katalinux.Profile, error) {
	if x.QualificationPin != "" {
		return nil, ErrRejected
	}
	return katalinux.Load(x.ProfileFile, x.PublicKeyFile, x.EvidenceDirectory, x.JournalDirectory, base)
}
