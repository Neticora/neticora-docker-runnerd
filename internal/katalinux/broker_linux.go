//go:build linux

package katalinux

import (
	"context"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"os"
	"path/filepath"
)

// ClaimBroker excludes the legacy observer for the complete broker lifetime.
// It reuses the original evidence/ownership directories; it never imports,
// renames, recreates or clears allocation records.
func (p *Profile) ClaimBroker(installation, host string) (func(), error) {
	if os.Geteuid() != 0 || p.ObserverSocket != "" || installation == "" || host == "" {
		return nil, ErrQualification
	}
	lock, err := lockObserverLifecycle(p.EvidenceDirectory)
	if err != nil {
		return nil, err
	}
	p.storageInstallationID, p.storageHostID = installation, host
	return func() { lock.Close() }, nil
}

// BrokerAbsence also supports a container retired before its VM was started.
// The original prepared witness must still prove all physical disposal facts.
func (p *Profile) BrokerAbsence(ctx context.Context, id string, plan dockerengine.Plan) error {
	raw, err := hostfs.ReadPrivate(filepath.Join(p.EvidenceDirectory, plan.Name+".json"), 32768)
	var record Evidence
	if err != nil || readEvidence(raw, &record) != nil || record.Version != "runnerd09-physical-v1" || record.Profile != p.ID || record.Container != id || record.SpecHash != plan.Config.Labels[dockerengine.LabelPrefix+"spec"] || record.Generation != plan.Config.Labels[dockerengine.LabelPrefix+"generation"] {
		return ErrQualification
	}
	a := record.Absence
	if a == nil || !a.ContainerAbsent || !a.SandboxAbsent || !a.VMAbsent || !a.NetworkRemoved || !a.StorageRemoved || a.VerifiedAt == "" || a.ObservationSource != "qualified-host-procfs-runtime-state-v1" || (!record.Prepared && len(record.Processes) != 2) {
		return ErrQualification
	}
	return p.CheckReadOnlyAbsence(ctx, id, plan, record)
}
