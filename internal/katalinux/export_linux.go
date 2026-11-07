//go:build linux

package katalinux

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

// PhysicalEvidence exports only a completed host-owned witness. The root helper
// rechecks absence read-only; this endpoint never cleans, creates or grants work.
func (p *Profile) PhysicalEvidence(ctx context.Context, id string, plan dockerengine.Plan) (Evidence, error) {
	var record Evidence
	if !ownedName(plan.Name) {
		return record, ErrQualification
	}
	if p.ObserverSocket != "" {
		raw, err := p.request(ctx, "evidence", id, plan)
		if err != nil {
			return record, err
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&record) != nil {
			return record, ErrQualification
		}
	} else {
		raw, err := hostfs.ReadPrivate(filepath.Join(p.EvidenceDirectory, plan.Name+".json"), 32768)
		if err != nil || readEvidence(raw, &record) != nil {
			return record, ErrQualification
		}
	}
	a := record.Absence
	if record.Version != "runnerd09-physical-v1" || record.Profile != p.ID || record.Container != id || record.SpecHash != plan.Config.Labels[dockerengine.LabelPrefix+"spec"] || record.Generation != plan.Config.Labels[dockerengine.LabelPrefix+"generation"] || record.Prepared || len(record.Processes) != 2 || a == nil || !a.ContainerAbsent || !a.SandboxAbsent || !a.VMAbsent || !a.NetworkRemoved || !a.StorageRemoved || a.VerifiedAt == "" || a.ObservationSource != "qualified-host-procfs-runtime-state-v1" {
		return record, ErrQualification
	}
	if p.Manifest.Version == MultiBlockVersion {
		group := record.Cgroup
		if group == nil || !a.CgroupRemoved || group.Phase != "released" || group.Profile != p.ID || group.Name != plan.Name || group.Unit != hostCgroupUnit(plan.Name) || group.Path != hostCgroupPath(plan.Name) || group.Inode == 0 || group.Device == 0 {
			return record, ErrQualification
		}
		// The unprivileged agent receives this proof from the authenticated
		// root observer; only that observer can inspect protected host state.
		if p.ObserverSocket == "" && p.checkReleasedHostCgroup(ctx, plan, group) != nil {
			return record, ErrQualification
		}
	}
	return record, nil
}

func (p *Profile) CheckReadOnlyAbsence(ctx context.Context, id string, plan dockerengine.Plan, record Evidence) error {
	if err := p.checkReleasedHostCgroup(ctx, plan, record.Cgroup); err != nil {
		return err
	}
	if p.layout() != nil {
		return ErrQualification
	}
	if err := p.priorProcessesAbsent(record.Processes); err != nil {
		return err
	}
	processes, err := p.processes(ctx, id)
	if err != nil || len(processes) != 0 {
		return ErrQualification
	}
	for _, root := range p.Manifest.SandboxRoots {
		if _, err = os.Lstat(filepath.Join(root, id)); !errors.Is(err, os.ErrNotExist) {
			return ErrQualification
		}
	}
	if p.Manifest.Storage.Block != nil {
		r, e := p.blockRecord(plan)
		if e != nil || record.Block == nil || !sameAllocation(*record.Block, r) || record.Absence == nil || !record.Absence.DeviceDetached || !record.Absence.MountsRemoved {
			return ErrQualification
		}
		return p.blockReleased(plan, r)
	}
	for _, fs := range []Filesystem{p.Manifest.Storage.Graph, p.Manifest.Storage.Workspace} {
		if _, err = os.Lstat(filepath.Join(fs.Root, plan.Name)); !errors.Is(err, os.ErrNotExist) {
			return ErrQualification
		}
	}
	return nil
}

func (p *Profile) priorProcessesAbsent(processes []Process) error {
	for _, prior := range processes {
		if prior.PID < 1 || (prior.Executable != p.Manifest.QEMUBinary && prior.Executable != p.Manifest.ShimBinary) {
			return ErrQualification
		}
		if _, err := strconv.ParseUint(prior.Start, 10, 64); err != nil {
			return ErrQualification
		}
		state, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(prior.PID), "stat"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return ErrQualification
		}
		close := bytes.LastIndexByte(state, ')')
		if close < 0 {
			return ErrQualification
		}
		fields := strings.Fields(string(state[close+1:]))
		if len(fields) < 20 || fields[19] == prior.Start {
			return ErrQualification
		}
	}
	return nil
}
