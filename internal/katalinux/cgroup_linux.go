//go:build linux

package katalinux

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"golang.org/x/sys/unix"
)

const hostCgroupRoot = "/sys/fs/cgroup"

type cgroupOutput struct{ bytes.Buffer }

func (b *cgroupOutput) Write(p []byte) (int, error) {
	if len(p) > 65536-b.Len() {
		return 0, ErrQualification
	}
	return b.Buffer.Write(p)
}

// Only pinned executables, fixed verbs and digest-derived unit names reach the
// system manager. No caller environment, shell, arbitrary unit or host path is
// accepted. Per-execution units are transient; persistent host policy is intact.
func (p *Profile) cgroupCommand(ctx context.Context, binary string, args ...string) (string, error) {
	if os.Geteuid() != 0 || p.Manifest.HostCgroup == nil || digestFile(binary, p.Manifest.Files[binary]) != nil {
		return "", ErrQualification
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_PAGER=cat"}
	command.WaitDelay = 2 * time.Second
	output := &cgroupOutput{}
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	return output.String(), err
}

func (p *Profile) cgroupUnitStatus(ctx context.Context, name string) (map[string]string, error) {
	if !ownedName(name) || p.Manifest.HostCgroup == nil {
		return nil, ErrQualification
	}
	raw, err := p.cgroupCommand(ctx, p.Manifest.HostCgroup.SystemctlBinary,
		"--no-pager", "--no-ask-password", "show", "--property=LoadState,ActiveState,Description,Transient,ControlGroup,FragmentPath,SourcePath,DropInPaths", "--", hostCgroupUnit(name))
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		_, duplicate := fields[key]
		if !ok || duplicate {
			return nil, ErrQualification
		}
		fields[key] = value
	}
	if len(fields) != 8 || (err != nil && !cgroupUnitMissing(fields)) {
		return nil, ErrQualification
	}
	for _, key := range []string{"LoadState", "ActiveState", "Description", "Transient", "ControlGroup", "FragmentPath", "SourcePath", "DropInPaths"} {
		if _, ok := fields[key]; !ok {
			return nil, ErrQualification
		}
	}
	return fields, nil
}

func cgroupUnitMissing(status map[string]string) bool {
	// systemd synthesizes an inactive implicit slice even before creation.
	// Configured files/drop-ins and transient units are never empty capacity.
	return status["ActiveState"] == "inactive" && status["ControlGroup"] == "" && status["FragmentPath"] == "" && status["SourcePath"] == "" && status["DropInPaths"] == "" && (status["LoadState"] == "not-found" || (status["LoadState"] == "loaded" && status["Transient"] == "no"))
}

func cgroupDescription(record CgroupRecord) string {
	return "Neticora Runnerd " + record.Name + " " + record.Profile + " " + record.Owner
}

func (p *Profile) cgroupRecord(plan dockerengine.Plan) (CgroupRecord, error) {
	var record CgroupRecord
	if !ownedName(plan.Name) || p.Manifest.HostCgroup == nil || plan.HostConfig == nil || plan.HostConfig.CgroupParent != hostCgroupUnit(plan.Name) {
		return record, ErrQualification
	}
	root, err := hostfs.OpenState(p.EvidenceDirectory)
	if err != nil {
		return record, err
	}
	defer root.Close()
	if err = readCheckedBlockJSON(root, plan.Name+".cgroup.json", &record); err != nil {
		return record, err
	}
	cpu, _ := strconv.ParseUint(p.Manifest.Budget.Effective.CpuMillis, 10, 64)
	memory, _ := strconv.ParseUint(p.Manifest.Budget.Effective.MemoryBytes, 10, 64)
	owner, decodeErr := hex.DecodeString(record.Owner)
	if record.Version != "runnerd09-host-cgroup-v1" || record.Profile != p.ID || record.Name != plan.Name || record.Unit != hostCgroupUnit(plan.Name) || record.Path != hostCgroupPath(plan.Name) || decodeErr != nil || len(owner) != 32 || hex.EncodeToString(owner) != record.Owner || record.CPUQuota != cpu*1000 || record.MemoryBytes != memory || record.PidsLimit != p.Manifest.HostCgroup.PidsLimit || len(record.BootID) != 36 {
		return record, ErrQualification
	}
	switch record.Phase {
	case "creating":
		if record.Device != 0 || record.Inode != 0 {
			return record, ErrQualification
		}
	case "released":
		if (record.Device == 0) != (record.Inode == 0) {
			return record, ErrQualification
		}
	case "ready", "releasing":
		if record.Device == 0 || record.Inode == 0 {
			return record, ErrQualification
		}
	default:
		return record, ErrQualification
	}
	boot, bootErr := hex.DecodeString(strings.ReplaceAll(record.BootID, "-", ""))
	if bootErr != nil || len(boot) != 16 || record.BootID != fmt.Sprintf("%x-%x-%x-%x-%x", boot[:4], boot[4:6], boot[6:8], boot[8:10], boot[10:]) {
		return record, ErrQualification
	}
	return record, nil
}

func (p *Profile) persistCgroup(record CgroupRecord) error {
	root, err := hostfs.OpenState(p.EvidenceDirectory)
	if err != nil {
		return err
	}
	defer root.Close()
	return writeCheckedBlockJSON(root, record.Name+".cgroup.json", record)
}

func currentCgroupBoot() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if len(value) != 36 {
		return "", ErrQualification
	}
	return value, nil
}

func inspectCgroup(record CgroupRecord) (syscall.Stat_t, bool, error) {
	var stat syscall.Stat_t
	path := hostCgroupRoot + record.Path
	if record.Path != hostCgroupPath(record.Name) || record.Path == "" {
		return stat, false, ErrQualification
	}
	if _, err := os.Lstat(path); err != nil {
		return stat, false, err
	}
	if hostfs.CheckAncestors(path) != nil || syscall.Stat(path, &stat) != nil || stat.Uid != 0 {
		return stat, false, ErrQualification
	}
	var fs syscall.Statfs_t
	if syscall.Statfs(path, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return stat, false, ErrQualification
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return stat, false, err
	}
	defer root.Close()
	read := func(name string) (string, error) {
		raw, err := root.ReadFile(name)
		if err != nil || len(raw) > 4096 {
			return "", ErrQualification
		}
		return strings.TrimSpace(string(raw)), nil
	}
	cpu, err := read("cpu.max")
	parts := strings.Fields(cpu)
	if err != nil || len(parts) != 2 {
		return stat, false, ErrQualification
	}
	quota, e := strconv.ParseUint(parts[0], 10, 64)
	period, e2 := strconv.ParseUint(parts[1], 10, 64)
	if e != nil || e2 != nil || period < 1000 || period > 1000000 || quota == 0 || quota > 128*period || quota*1000000 != record.CPUQuota*period {
		return stat, false, ErrQualification
	}
	for file, expected := range map[string]string{
		"memory.max": strconv.FormatUint(record.MemoryBytes, 10), "memory.swap.max": "0",
		"pids.max": strconv.FormatUint(record.PidsLimit, 10),
	} {
		value, err := read(file)
		if err != nil || value != expected {
			return stat, false, ErrQualification
		}
	}
	events, err := read("cgroup.events")
	if err != nil {
		return stat, false, err
	}
	populated := ""
	for _, line := range strings.Split(events, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[0] == "populated" {
			if populated != "" {
				return stat, false, ErrQualification
			}
			populated = parts[1]
		}
	}
	if populated != "0" && populated != "1" {
		return stat, false, ErrQualification
	}
	return stat, populated == "1", nil
}

func (p *Profile) prepareHostCgroup(ctx context.Context, plan dockerengine.Plan) error {
	if p.Manifest.Version != MultiBlockVersion {
		return nil
	}
	if validateHostCgroup(p.Manifest) != nil || !ownedName(plan.Name) || plan.HostConfig.CgroupParent != hostCgroupUnit(plan.Name) {
		return ErrQualification
	}
	boot, err := currentCgroupBoot()
	if err != nil {
		return err
	}
	record, err := p.cgroupRecord(plan)
	if errors.Is(err, os.ErrNotExist) {
		status, e := p.cgroupUnitStatus(ctx, plan.Name)
		if e != nil || !cgroupUnitMissing(status) {
			return ErrQualification
		}
		if _, e = os.Lstat(hostCgroupRoot + hostCgroupPath(plan.Name)); !errors.Is(e, os.ErrNotExist) {
			return ErrQualification
		}
		var owner [32]byte
		if _, e = rand.Read(owner[:]); e != nil {
			return e
		}
		cpu, _ := strconv.ParseUint(p.Manifest.Budget.Effective.CpuMillis, 10, 64)
		memory, _ := strconv.ParseUint(p.Manifest.Budget.Effective.MemoryBytes, 10, 64)
		record = CgroupRecord{Version: "runnerd09-host-cgroup-v1", Profile: p.ID, Name: plan.Name,
			Unit: hostCgroupUnit(plan.Name), Path: hostCgroupPath(plan.Name), Owner: hex.EncodeToString(owner[:]),
			BootID: boot, CPUQuota: cpu * 1000, MemoryBytes: memory, PidsLimit: p.Manifest.HostCgroup.PidsLimit, Phase: "creating"}
		if err = p.persistCgroup(record); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if record.BootID != boot || (record.Phase != "creating" && record.Phase != "ready") {
		return ErrQualification
	}
	if record.Phase == "ready" {
		_, err := p.verifyHostCgroup(ctx, plan, nil)
		return err
	}
	status, err := p.cgroupUnitStatus(ctx, plan.Name)
	if err != nil {
		return err
	}
	if cgroupUnitMissing(status) {
		if _, e := os.Lstat(hostCgroupRoot + record.Path); !errors.Is(e, os.ErrNotExist) {
			return ErrQualification
		}
		properties := [][3]string{
			{"Description", "s", cgroupDescription(record)},
			{"CPUAccounting", "b", "true"}, {"CPUQuotaPerSecUSec", "t", strconv.FormatUint(record.CPUQuota, 10)},
			{"CPUQuotaPeriodUSec", "t", "100000"}, {"MemoryAccounting", "b", "true"},
			{"MemoryMax", "t", strconv.FormatUint(record.MemoryBytes, 10)}, {"MemorySwapMax", "t", "0"},
			{"TasksAccounting", "b", "true"},
			{"TasksMax", "t", strconv.FormatUint(record.PidsLimit, 10)}, {"StopWhenUnneeded", "b", "false"},
			{"CollectMode", "s", "inactive-or-failed"},
		}
		args := []string{"--system", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "StartTransientUnit", "ssa(sv)a(sa(sv))", record.Unit, "fail", strconv.Itoa(len(properties))}
		for _, property := range properties {
			args = append(args, property[:]...)
		}
		args = append(args, "0")
		if output, createErr := p.cgroupCommand(ctx, p.Manifest.HostCgroup.BusctlBinary, args...); createErr != nil {
			// A lost response never erases the creating intent or replaces a unit.
			return fmt.Errorf("%w: transient host slice creation: %v: %s", ErrQualification, createErr, strings.TrimSpace(output))
		}
		status, err = p.cgroupUnitStatus(ctx, plan.Name)
	}
	if err != nil || status["LoadState"] != "loaded" || status["ActiveState"] != "active" || status["Transient"] != "yes" || status["ControlGroup"] != record.Path || status["Description"] != cgroupDescription(record) {
		return ErrQualification
	}
	stat, populated, err := inspectCgroup(record)
	if err != nil || populated {
		return ErrQualification
	}
	record.Device, record.Inode, record.Phase = uint64(stat.Dev), stat.Ino, "ready"
	return p.persistCgroup(record)
}

func (p *Profile) verifyHostCgroup(ctx context.Context, plan dockerengine.Plan, processes []Process) (*CgroupRecord, error) {
	if p.Manifest.Version != MultiBlockVersion {
		return nil, nil
	}
	record, err := p.cgroupRecord(plan)
	boot, e := currentCgroupBoot()
	if err != nil || e != nil || record.BootID != boot || record.Phase != "ready" {
		return nil, ErrQualification
	}
	status, err := p.cgroupUnitStatus(ctx, plan.Name)
	if err != nil || status["LoadState"] != "loaded" || status["ActiveState"] != "active" || status["Transient"] != "yes" || status["ControlGroup"] != record.Path || status["Description"] != cgroupDescription(record) {
		return nil, ErrQualification
	}
	stat, _, err := inspectCgroup(record)
	if err != nil || uint64(stat.Dev) != record.Device || stat.Ino != record.Inode {
		return nil, ErrQualification
	}
	for _, process := range processes {
		path := filepath.Join("/proc", strconv.Itoa(process.PID))
		start := func() (string, error) {
			raw, err := os.ReadFile(path + "/stat")
			end := bytes.LastIndexByte(raw, ')')
			if err != nil || end < 0 {
				return "", ErrQualification
			}
			fields := strings.Fields(string(raw[end+1:]))
			if len(fields) < 20 {
				return "", ErrQualification
			}
			return fields[19], nil
		}
		before, err := start()
		if err != nil || before != process.Start {
			return nil, ErrQualification
		}
		raw, err := os.ReadFile(path + "/cgroup")
		if err != nil || len(raw) > 4096 {
			return nil, ErrQualification
		}
		line := strings.TrimSpace(string(raw))
		if strings.Contains(line, "\n") || !strings.HasPrefix(line, "0::") {
			return nil, ErrQualification
		}
		group := strings.TrimPrefix(line, "0::")
		if group != record.Path && !strings.HasPrefix(group, record.Path+"/") {
			return nil, fmt.Errorf("%w: owned process %s pid %d outside %s", ErrQualification, process.Executable, process.PID, record.Path)
		}
		after, err := start()
		if err != nil || after != before {
			return nil, ErrQualification
		}
	}
	return &record, nil
}

func (p *Profile) hostCgroupAbsent(ctx context.Context, plan dockerengine.Plan) error {
	status, err := p.cgroupUnitStatus(ctx, plan.Name)
	if err != nil || !cgroupUnitMissing(status) {
		return ErrQualification
	}
	if _, err := os.Lstat(hostCgroupRoot + hostCgroupPath(plan.Name)); !errors.Is(err, os.ErrNotExist) {
		return ErrQualification
	}
	return nil
}

// Stop only an empty, identity-verified owned slice. Never use systemd stop to
// kill uncertain work, and never infer cgroup absence from container absence.
func (p *Profile) releaseHostCgroup(ctx context.Context, plan dockerengine.Plan) (*CgroupRecord, error) {
	if p.Manifest.Version != MultiBlockVersion {
		return nil, nil
	}
	record, err := p.cgroupRecord(plan)
	if errors.Is(err, os.ErrNotExist) {
		return nil, p.hostCgroupAbsent(ctx, plan)
	}
	if err != nil {
		return nil, err
	}
	if record.Phase == "released" {
		return &record, p.hostCgroupAbsent(ctx, plan)
	}
	if record.Phase == "creating" && record.Inode == 0 {
		// A creating intent can own a unit after a lost create response. Bind
		// its identity only after validating its owner and exact kernel limits.
		status, e := p.cgroupUnitStatus(ctx, plan.Name)
		if e != nil {
			return nil, e
		}
		if !cgroupUnitMissing(status) {
			if status["Description"] != cgroupDescription(record) || status["Transient"] != "yes" || status["ControlGroup"] != record.Path {
				return nil, ErrQualification
			}
			stat, populated, e := inspectCgroup(record)
			if e != nil || populated {
				return nil, ErrQualification
			}
			record.Device, record.Inode = uint64(stat.Dev), stat.Ino
		}
	}
	status, err := p.cgroupUnitStatus(ctx, plan.Name)
	if err != nil {
		return nil, err
	}
	if !cgroupUnitMissing(status) {
		boot, e := currentCgroupBoot()
		if e != nil || boot != record.BootID || status["Description"] != cgroupDescription(record) || status["Transient"] != "yes" || status["ControlGroup"] != record.Path {
			return nil, ErrQualification
		}
		stat, populated, e := inspectCgroup(record)
		if e != nil || populated || uint64(stat.Dev) != record.Device || stat.Ino != record.Inode {
			return nil, ErrQualification
		}
		record.Phase = "releasing"
		if err := p.persistCgroup(record); err != nil {
			return nil, err
		}
		if _, err = p.cgroupCommand(ctx, p.Manifest.HostCgroup.SystemctlBinary, "--no-pager", "--no-ask-password", "stop", "--", record.Unit); err != nil {
			return nil, ErrQualification
		}
	}
	for i := 0; i < 2; i++ {
		if err := p.hostCgroupAbsent(ctx, plan); err != nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	record.Phase = "released"
	if err := p.persistCgroup(record); err != nil {
		return nil, err
	}
	return &record, nil
}

func (p *Profile) checkReleasedHostCgroup(ctx context.Context, plan dockerengine.Plan, expected *CgroupRecord) error {
	if p.Manifest.Version != MultiBlockVersion {
		return nil
	}
	record, err := p.cgroupRecord(plan)
	if err != nil || expected == nil || record != *expected || record.Phase != "released" {
		return fmt.Errorf("%w: host cgroup release evidence", ErrQualification)
	}
	return p.hostCgroupAbsent(ctx, plan)
}
