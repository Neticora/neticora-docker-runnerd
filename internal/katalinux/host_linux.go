//go:build linux

package katalinux

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

type fileStamp struct {
	Dev, Inode   uint64
	Size         int64
	Mode, UID    uint32
	Mtime, Ctime syscall.Timespec
}

var fileHashes sync.Map

func stamp(s *syscall.Stat_t) fileStamp {
	return fileStamp{uint64(s.Dev), s.Ino, s.Size, s.Mode, s.Uid, s.Mtim, s.Ctim}
}

func digestFile(path, expected string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(expected) != 64 {
		return ErrQualification
	}
	if hostfs.CheckAncestors(filepath.Dir(path)) != nil {
		return ErrQualification
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if e != nil {
		return ErrQualification
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	before, e := f.Stat()
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 {
		return ErrQualification
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) || before.Size() > 4<<30 {
		return ErrQualification
	}
	cacheKey := path + "\x00" + expected
	if cached, ok := fileHashes.Load(cacheKey); ok && cached == stamp(st) {
		return nil
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, 4<<30+1)); e != nil {
		return ErrQualification
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || hex.EncodeToString(h.Sum(nil)) != expected {
		return ErrQualification
	}
	end, ok := after.Sys().(*syscall.Stat_t)
	if !ok || stamp(end) != stamp(st) {
		return ErrQualification
	}
	fileHashes.Store(cacheKey, stamp(end))
	return nil
}
func (p *Profile) layout() error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return ErrQualification
	}
	k, e := os.ReadFile("/proc/sys/kernel/osrelease")
	if e != nil || strings.TrimSpace(string(k)) != p.Manifest.HostKernel {
		return ErrQualification
	}
	for path, hash := range p.Manifest.Files {
		if digestFile(path, hash) != nil {
			return ErrQualification
		}
	}
	var journal syscall.Stat_t
	if syscall.Stat(p.JournalDirectory, &journal) != nil {
		return ErrQualification
	}
	seen := map[uint64]bool{uint64(journal.Dev): true}
	var docker syscall.Stat_t
	if syscall.Stat(p.Manifest.Storage.DockerRoot, &docker) != nil || docker.Dev == journal.Dev {
		return ErrQualification
	}
	seen[uint64(docker.Dev)] = true
	for _, fs := range p.storageFilesystems() {
		device, identityErr := p.storageDevice(fs)
		if identityErr != nil {
			return identityErr
		}
		if hostfs.CheckAncestors(fs.Root) != nil {
			return ErrQualification
		}
		var stat syscall.Stat_t
		var size syscall.Statfs_t
		if syscall.Stat(fs.Root, &stat) != nil || syscall.Statfs(fs.Root, &size) != nil || size.Type != 0xef53 || uint64(stat.Dev) != device || seen[device] || uint64(size.Blocks)*uint64(size.Bsize) != fs.Bytes {
			return ErrQualification
		}
		// Require an actual mount point; a same-device directory or sparse file
		// cannot impersonate a physically bounded execution filesystem.
		var parent syscall.Stat_t
		if syscall.Stat(filepath.Dir(fs.Root), &parent) != nil || parent.Dev == stat.Dev {
			return ErrQualification
		}
		seen[device] = true
		// A sparse loop image is not an accepted physical backing mechanism.
		major := (device >> 8) & 0xfff
		minor := (device & 0xff) | ((device >> 12) & 0xfff00)
		if major == 0 {
			return ErrQualification
		}
		block := filepath.Join("/sys/dev/block", strconv.FormatUint(major, 10)+":"+strconv.FormatUint(minor, 10))
		if _, err := os.Stat(block); err != nil {
			return ErrQualification
		}
		// This initial mechanism excludes loop images and device-mapper thin or
		// otherwise opaque pools; additional backing mechanisms need qualification.
		if _, err := os.Stat(filepath.Join(block, "dm")); err == nil {
			return ErrQualification
		} else if !errors.Is(err, os.ErrNotExist) {
			return ErrQualification
		}
		if _, err := os.Stat(filepath.Join(block, "loop")); err == nil {
			return ErrQualification
		} else if !errors.Is(err, os.ErrNotExist) {
			return ErrQualification
		}
	}
	return nil
}
func (p *Profile) Check(now time.Time) error {
	if err := p.RequireLaunchStorage(); err != nil {
		return err
	}
	if p == nil || p.validate() != nil {
		return ErrQualification
	}
	verified, e := time.Parse(time.RFC3339Nano, p.Manifest.VerifiedAt)
	expiry, e2 := time.Parse(time.RFC3339Nano, p.Manifest.ExpiresAt)
	if e != nil || e2 != nil || verified.After(now) || !expiry.After(now) || expiry.Sub(verified) > 24*time.Hour || expiry.Before(verified) {
		return ErrQualification
	}
	if p.ObserverSocket != "" {
		return p.remote(context.Background(), "check", "", dockerengine.Plan{})
	}
	// A signed device reconciliation permits recovery only. New admission
	// needs a newly qualified profile for the actual session device numbers.
	if p.layout() != nil || p.launchStorageSession() != nil {
		return ErrQualification
	}
	for _, root := range []string{p.JournalDirectory, p.Manifest.Storage.DockerRoot} {
		var s syscall.Statfs_t
		if syscall.Statfs(root, &s) != nil || uint64(s.Bavail)*uint64(s.Bsize) < p.Manifest.Storage.ManagementFreeBytes {
			return ErrQualification
		}
	}
	return nil
}
func (p *Profile) Prepare(plan dockerengine.Plan) error {
	if p.ObserverSocket != "" {
		return p.remote(context.Background(), "prepare", "", plan)
	}
	if p.Check(time.Now()) != nil || !ownedName(plan.Name) {
		return ErrQualification
	}
	if p.Manifest.Storage.Block != nil {
		return p.prepareBlock(context.Background(), plan)
	}
	for _, fs := range []Filesystem{p.Manifest.Storage.Graph, p.Manifest.Storage.Workspace} {
		root, e := hostfs.OpenState(fs.Root)
		if e != nil {
			return e
		}
		dir, e := root.Open(".")
		if e != nil {
			root.Close()
			return e
		}
		names, e := dir.Readdirnames(-1)
		dir.Close()
		if e != nil {
			root.Close()
			return e
		}
		for _, name := range names {
			if name != plan.Name && name != "lost+found" {
				root.Close()
				return ErrQualification
			}
		}
		e = root.Mkdir(plan.Name, 0700)
		fresh := e == nil
		root.Close()
		if e != nil && !errors.Is(e, os.ErrExist) {
			return e
		}
		target := filepath.Join(fs.Root, plan.Name)
		wantUID := os.Geteuid()
		if fs.Root == p.Manifest.Storage.Workspace.Root {
			wantUID = p.Base.RunnerUID
		}
		if fresh && os.Chown(target, wantUID, wantUID) != nil {
			return ErrQualification
		}
		info, e := os.Lstat(target)
		if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			return ErrQualification
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != wantUID {
			return ErrQualification
		}
	}
	return nil
}
func ownedName(name string) bool {
	if len(name) != 68 || !strings.HasPrefix(name, "nrd-") {
		return false
	}
	_, e := hex.DecodeString(name[4:])
	return e == nil
}

// A guest marker is a liveness hint only. It never proves host isolation,
// ownership, launch authorization or physical teardown. The Docker-observed
// start timestamp enforces a separate hard lifetime even if a guest forges it.
func (p *Profile) Healthy(plan dockerengine.Plan, startedAt string, now time.Time) bool {
	start, e := time.Parse(time.RFC3339Nano, startedAt)
	if e != nil || start.After(now) || now.Sub(start) > time.Duration(p.Manifest.Deadlines.ExecutionSeconds)*time.Second {
		return false
	}
	raw, e := hostfs.ReadPrivate(filepath.Join(p.HealthRoot(), plan.Name, "supervisor-health.json"), 1024)
	if e != nil {
		return now.Sub(start) <= time.Duration(p.Manifest.Deadlines.StartupSeconds)*time.Second
	}
	if _, e = protocol.CanonicalizeJSON(raw); e != nil {
		return false
	}
	var health struct {
		Version    string `json:"version"`
		ObservedAt string `json:"observedAt"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&health) != nil || health.Version != "runnerd09-supervisor-health-v1" {
		return false
	}
	observed, e := time.Parse(time.RFC3339Nano, health.ObservedAt)
	return e == nil && !observed.Before(start) && observed.Sub(now) <= 5*time.Second && now.Sub(observed) <= time.Duration(p.Manifest.Deadlines.HeartbeatSeconds)*time.Second
}

// Only the service owner provisions this volatile, per-attempt output directory.
// Host reads reject mismatched ownership/mode if a guest UID mapping changes.
func (p *Profile) PrepareHealth(plan dockerengine.Plan) error {
	if !ownedName(plan.Name) {
		return ErrQualification
	}
	root, err := hostfs.OpenState(p.HealthRoot())
	if err != nil {
		return err
	}
	defer root.Close()
	if err = root.Mkdir(plan.Name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	dir, err := hostfs.OpenState(filepath.Join(p.HealthRoot(), plan.Name))
	if err != nil {
		return err
	}
	return dir.Close()
}

func (p *Profile) CleanHealth(plan dockerengine.Plan) {
	if !ownedName(plan.Name) {
		return
	}
	dir := filepath.Join(p.HealthRoot(), plan.Name)
	root, err := hostfs.OpenState(dir)
	if err != nil {
		return
	}
	_ = root.Remove("supervisor-health.json")
	_ = root.Close()
	_ = os.Remove(dir) // Never recursively delete unexpected guest output.
}

func readEvidence(raw []byte, record *Evidence) error {
	if len(raw) > 32768 {
		return ErrQualification
	}
	if _, e := protocol.CanonicalizeJSON(raw); e != nil {
		return ErrQualification
	}
	var envelope struct {
		Record Evidence `json:"record"`
		Hash   string   `json:"hash"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil {
		return ErrQualification
	}
	body, _ := json.Marshal(envelope.Record)
	body, e := protocol.CanonicalizeJSON(body)
	if e != nil {
		return ErrQualification
	}
	sum := sha256.Sum256(body)
	if envelope.Hash != hex.EncodeToString(sum[:]) {
		return ErrQualification
	}
	*record = envelope.Record
	return nil
}

// processes takes a complete host procfs inventory, never a guest self-report or
// a pgrep name match. Only exact sandbox IDs in qualified QEMU/shim argument
// positions identify candidates. Unknown binaries/permissions retain the hold.
func (p *Profile) processes(ctx context.Context, id string) ([]Process, error) {
	if len(id) != 64 {
		return nil, ErrQualification
	}
	if _, e := hex.DecodeString(id); e != nil {
		return nil, ErrQualification
	}
	entries, e := os.ReadDir("/proc")
	if e != nil {
		return nil, ErrQualification
	}
	out := []Process{}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		pid, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		dir := filepath.Join("/proc", entry.Name())
		raw, e := os.ReadFile(filepath.Join(dir, "cmdline"))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return nil, ErrQualification
		}
		args := strings.Split(string(raw), "\x00")
		matched := false
		for i, a := range args {
			if i == 0 {
				continue
			}
			if args[i-1] == "-id" && a == id {
				matched = true
			}
			if args[i-1] == "-name" && strings.Split(a, ",")[0] == p.Manifest.VMNamePrefix+id {
				matched = true
			}
		}
		if !matched {
			continue
		}
		exe, e := os.Readlink(filepath.Join(dir, "exe"))
		if e != nil || !strings.ContainsRune(exe, '/') {
			return nil, ErrQualification
		}
		if exe != p.Manifest.QEMUBinary && exe != p.Manifest.ShimBinary {
			return nil, ErrQualification
		}
		if digestFile(exe, p.Manifest.Files[exe]) != nil {
			return nil, ErrQualification
		}
		state, e := os.ReadFile(filepath.Join(dir, "stat"))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return nil, ErrQualification
		}
		close := bytes.LastIndexByte(state, ')')
		if close < 0 {
			return nil, ErrQualification
		}
		fields := strings.Fields(string(state[close+1:]))
		if len(fields) < 20 {
			return nil, ErrQualification
		}
		out = append(out, Process{PID: pid, Start: fields[19], Executable: exe})
	}
	return out, nil
}
func (p *Profile) Capture(ctx context.Context, id string, plan dockerengine.Plan) error {
	if p.ObserverSocket != "" {
		return p.remote(ctx, "capture", id, plan)
	}
	if p.layout() != nil || !ownedName(plan.Name) {
		return ErrQualification
	}
	processes, e := p.processes(ctx, id)
	if e != nil {
		return e
	}
	// A running guest requires both the trusted shim and VMM. Missing process
	// identity never authorizes adoption, another launch, or physical release.
	vm, shim := 0, 0
	for _, v := range processes {
		if v.Executable == p.Manifest.QEMUBinary {
			vm++
		}
		if v.Executable == p.Manifest.ShimBinary {
			shim++
		}
	}
	if vm != 1 || shim != 1 || len(processes) != 2 {
		return ErrQualification
	}
	root, e := hostfs.OpenState(p.EvidenceDirectory)
	if e != nil {
		return e
	}
	defer root.Close()
	record := Evidence{Version: "runnerd09-physical-v1", Profile: p.ID, Container: id, SpecHash: plan.Config.Labels[dockerengine.LabelPrefix+"spec"], Generation: plan.Config.Labels[dockerengine.LabelPrefix+"generation"], ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Processes: processes}
	record.Cgroup, e = p.verifyHostCgroup(ctx, plan, processes)
	if e != nil {
		return e
	}
	record.Sandboxes, e = p.captureSandboxDirectories(id)
	if e != nil {
		return e
	}
	if p.Manifest.Storage.Block != nil {
		block, err := p.blockRecord(plan)
		if err != nil || p.verifyBlock(plan) != nil || verifyVMMBlock(processes, block, p.Manifest.QEMUBinary) != nil {
			return ErrQualification
		}
		record.Block = &block
	}

	file := plan.Name + ".json"
	if old, e := root.ReadFile(file); e == nil {
		var previous Evidence
		if readEvidence(old, &previous) != nil || previous.Profile != record.Profile || previous.Container != id || previous.SpecHash != record.SpecHash || previous.Generation != record.Generation {
			return ErrQualification
		}
		if !previous.Prepared {
			if !slices.Equal(previous.Processes, processes) || !slices.Equal(previous.Sandboxes, record.Sandboxes) || !sameHostCgroup(previous.Cgroup, record.Cgroup) {
				return ErrQualification
			}
			return nil
		}
		for _, prior := range previous.Processes {
			if !slices.Contains(processes, prior) {
				return ErrQualification
			}
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return persist(root, file, record)
}
func persist(root *os.Root, file string, record Evidence) error {
	body, e := json.Marshal(record)
	if e != nil {
		return e
	}
	body, e = protocol.CanonicalizeJSON(body)
	if e != nil {
		return e
	}
	hash := sha256.Sum256(body)
	raw, e := json.Marshal(struct {
		Record Evidence `json:"record"`
		Hash   string   `json:"hash"`
	}{record, hex.EncodeToString(hash[:])})
	if e != nil {
		return e
	}
	tmp := file + "." + rand.Text()
	f, e := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if e = root.Rename(tmp, file); e != nil {
		return e
	}
	d, e := root.Open(".")
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (p *Profile) CapturePrepared(id string, plan dockerengine.Plan) error {
	if p.ObserverSocket != "" {
		return p.remote(context.Background(), "prepared", id, plan)
	}
	if !ownedName(plan.Name) || len(id) != 64 {
		return ErrQualification
	}
	root, e := hostfs.OpenState(p.EvidenceDirectory)
	if e != nil {
		return e
	}
	defer root.Close()
	processes, e := p.processes(context.Background(), id)
	if e != nil {
		return e
	}
	group, e := p.verifyHostCgroup(context.Background(), plan, processes)
	if e != nil {
		return e
	}
	file := plan.Name + ".json"
	if raw, e := root.ReadFile(file); e == nil {
		var old Evidence
		if readEvidence(raw, &old) != nil || old.Profile != p.ID || old.Container != id || old.SpecHash != plan.Config.Labels[dockerengine.LabelPrefix+"spec"] || old.Generation != plan.Config.Labels[dockerengine.LabelPrefix+"generation"] {
			return ErrQualification
		}
		if !old.Prepared || !sameHostCgroup(old.Cgroup, group) {
			return ErrQualification
		}
		for _, prior := range old.Processes {
			if !slices.Contains(processes, prior) {
				return ErrQualification
			}
		}
		return nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	record := Evidence{Version: "runnerd09-physical-v1", Profile: p.ID, Container: id, SpecHash: plan.Config.Labels[dockerengine.LabelPrefix+"spec"], Generation: plan.Config.Labels[dockerengine.LabelPrefix+"generation"], ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Prepared: true, Processes: processes}
	record.Cgroup = group
	if p.Manifest.Storage.Block != nil {
		block, err := p.blockRecord(plan)
		if err != nil || p.verifyBlock(plan) != nil {
			return ErrQualification
		}
		record.Block = &block
	}
	return persist(root, file, record)
}
func (p *Profile) VerifyAbsent(ctx context.Context, id string, plan dockerengine.Plan, guards ...func() error) error {
	if p.ObserverSocket != "" {
		return p.remote(ctx, "absent", id, plan)
	}
	if p.layout() != nil || !ownedName(plan.Name) {
		return ErrQualification
	}
	raw, e := hostfs.ReadPrivate(filepath.Join(p.EvidenceDirectory, plan.Name+".json"), 32768)
	if e != nil {
		return ErrQualification
	}
	var record Evidence
	if readEvidence(raw, &record) != nil || record.Version != "runnerd09-physical-v1" || record.Profile != p.ID || record.Container != id || record.SpecHash != plan.Config.Labels[dockerengine.LabelPrefix+"spec"] || record.Generation != plan.Config.Labels[dockerengine.LabelPrefix+"generation"] || (!record.Prepared && len(record.Processes) < 2) {
		return ErrQualification
	}
	verifyProcesses := func() error {
		for _, guard := range guards {
			if err := guard(); err != nil {
				return err
			}
		}
		for _, prior := range record.Processes {
			if prior.PID < 1 || (prior.Executable != p.Manifest.ShimBinary && prior.Executable != p.Manifest.QEMUBinary) {
				return ErrQualification
			}
			if _, e := strconv.ParseUint(prior.Start, 10, 64); e != nil {
				return ErrQualification
			}
			stat, e := os.ReadFile(filepath.Join("/proc", strconv.Itoa(prior.PID), "stat"))
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				return ErrQualification
			}
			close := bytes.LastIndexByte(stat, ')')
			if close < 0 {
				return ErrQualification
			}
			fields := strings.Fields(string(stat[close+1:]))
			if len(fields) < 20 || fields[19] == prior.Start {
				return ErrQualification
			}
		}
		processes, e := p.processes(ctx, id)
		if e != nil || len(processes) != 0 {
			return ErrQualification
		}
		return nil
	}
	verifyOwners := func() error {
		if err := verifyProcesses(); err != nil {
			return err
		}
		for _, root := range p.Manifest.SandboxRoots {
			if _, e := os.Lstat(filepath.Join(root, id)); !errors.Is(e, os.ErrNotExist) {
				return ErrQualification
			}
		}

		return nil
	}
	if p.Manifest.Version == MultiBlockVersion && len(record.Sandboxes) > 0 {
		guard := func() error {
			if err := verifyProcesses(); err != nil {
				return err
			}
			current, err := p.cgroupRecord(plan)
			if err != nil || record.Cgroup == nil || !sameHostCgroup(record.Cgroup, &current) {
				return ErrQualification
			}
			if _, err := os.Lstat(filepath.Join("/sys/fs/cgroup", current.Path)); errors.Is(err, os.ErrNotExist) {
				return nil
			}
			_, populated, err := inspectCgroup(current)
			if err != nil || populated {
				return ErrQualification
			}
			return nil
		}
		if err := p.removeSandboxResidue(ctx, id, record.Sandboxes, guard); err != nil {
			return err
		}
	}
	if err := verifyOwners(); err != nil {
		return err
	}
	if p.Manifest.Version == MultiBlockVersion {
		current, err := p.cgroupRecord(plan)
		if err != nil || record.Cgroup == nil || !sameHostCgroup(record.Cgroup, &current) {
			return ErrQualification
		}
	}
	if p.Manifest.Storage.Block != nil {
		block, err := p.blockRecord(plan)
		if err != nil {
			return err
		}
		if record.Block == nil || !sameAllocation(*record.Block, block) {
			return ErrQualification
		}
		if err = p.releaseBlock(ctx, plan, verifyOwners); err != nil {
			return err
		}
		released, err := p.blockRecord(plan)
		if err != nil || p.blockReleased(plan, released) != nil {
			return ErrQualification
		}
		record.Block = &released
	} else {

		// Remove only confined execution-owned storage. Failure (including UID or
		// detach uncertainty) preserves the durable common cleanup obligation.
		for _, fs := range []Filesystem{p.Manifest.Storage.Graph, p.Manifest.Storage.Workspace} {
			root, e := hostfs.OpenState(fs.Root)
			if e != nil {
				return e
			}
			if _, e := root.Lstat(plan.Name); e == nil {
				if e = noNestedMounts(filepath.Join(fs.Root, plan.Name)); e != nil {
					root.Close()
					return e
				}
				remaining := 1000000
				if e = removeOwned(ctx, root, plan.Name, fs.Device, 0, &remaining); e != nil {
					root.Close()
					return e
				}
			} else if !errors.Is(e, os.ErrNotExist) {
				root.Close()
				return e
			}
			_, e = root.Lstat(plan.Name)
			root.Close()
			if !errors.Is(e, os.ErrNotExist) {
				return ErrQualification
			}
		}
	}

	record.Cgroup, e = p.releaseHostCgroup(ctx, plan)
	if e != nil {
		return e
	}
	// Called only after the host observer's continuous Docker inspection and
	// bridge-endpoint verification; every retry repeats all physical checks.
	record.Absence = &PhysicalAbsence{DeviceDetached: p.Manifest.Storage.Block != nil, MountsRemoved: p.Manifest.Storage.Block != nil, ContainerAbsent: true, SandboxAbsent: true, VMAbsent: true, NetworkRemoved: true, StorageRemoved: true, VerifiedAt: time.Now().UTC().Format(time.RFC3339Nano), ObservationSource: "qualified-host-procfs-runtime-state-v1"}
	record.Absence.CgroupRemoved = p.Manifest.Version == MultiBlockVersion
	root, e := hostfs.OpenState(p.EvidenceDirectory)
	if e != nil {
		return e
	}
	defer root.Close()
	return persist(root, plan.Name+".json", record)
}

func noNestedMounts(path string) error {
	raw, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		return e
	}
	decode := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, "\\")
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		point := decode.Replace(fields[4])
		if point == path || strings.HasPrefix(point, path+string(filepath.Separator)) {
			return ErrQualification
		}
	}
	return nil
}

func removeOwned(ctx context.Context, root *os.Root, path string, device uint64, depth int, left *int) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if depth > 128 || *left <= 0 {
		return ErrQualification
	}
	*left = *left - 1
	info, e := root.Lstat(path)
	if e != nil {
		return e
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != device {
		return ErrQualification
	}
	if info.IsDir() {
		f, e := root.Open(path)
		if e != nil {
			return e
		}
		names, e := f.Readdirnames(-1)
		f.Close()
		if e != nil {
			return e
		}
		for _, name := range names {
			if e = removeOwned(ctx, root, filepath.Join(path, name), device, depth+1, left); e != nil {
				return e
			}
		}
	}
	return root.Remove(path)
}
