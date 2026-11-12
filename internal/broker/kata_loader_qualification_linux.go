//go:build linux && runnerd_qualification

package broker

import (
	"encoding/json"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

func loadKata(c Config, x KataConfig, base standardlinux.Settings) (*katalinux.Profile, error) {
	if x.QualificationPin == "" {
		return katalinux.Load(x.ProfileFile, x.PublicKeyFile, x.EvidenceDirectory, x.JournalDirectory, base)
	}
	raw, err := hostfs.ReadPrivate(x.ProfileFile, 131072)
	if err != nil {
		return nil, err
	}
	var envelope katalinux.LabEnvelope
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, ErrRejected
	}
	b := envelope.Binding
	if b.InstallationID != c.Scope.InstallationID || b.HostID != c.Scope.HostID || b.TenantID != c.Scope.TenantID || b.ServiceUID != int(c.ControllerUID) {
		return nil, ErrRejected
	}
	return katalinux.LoadQualification(x.ProfileFile, x.PublicKeyFile, x.QualificationPin, b, x.EvidenceDirectory, x.JournalDirectory, base)
}
