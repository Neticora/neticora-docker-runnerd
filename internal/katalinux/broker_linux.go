//go:build linux

package katalinux

import (
	"context"
	"errors"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"io"
	"os"
	"path/filepath"
	"syscall"
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
	p.brokerOwned = true
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

// Guest output retains the guest/service UID, under a root-private parent that
// the controller cannot traverse. It is a liveness hint, never authority.
func (p *Profile) brokerHealthDirectory(plan dockerengine.Plan, create bool) (*os.Root, error) {
	if !p.brokerOwned || !ownedName(plan.Name) {
		return nil, ErrQualification
	}
	root, err := hostfs.OpenState(p.HealthRoot())
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if create {
		err = root.Mkdir(plan.Name, 0700)
		if err == nil {
			err = root.Chown(plan.Name, p.Base.RunnerUID, p.Base.RunnerUID)
		}
		if err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	info, err := root.Lstat(plan.Name)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || int(st.Uid) != p.Base.RunnerUID || int(st.Gid) != p.Base.RunnerUID {
		return nil, ErrQualification
	}
	return root.OpenRoot(plan.Name)
}
func (p *Profile) brokerHealthRead(plan dockerengine.Plan) ([]byte, error) {
	root, err := p.brokerHealthDirectory(plan, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.OpenFile("supervisor-health.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 1024 || st.Nlink != 1 || int(st.Uid) != p.Base.RunnerUID || int(st.Gid) != p.Base.RunnerUID {
		return nil, ErrQualification
	}
	return io.ReadAll(io.LimitReader(f, 1025))
}
