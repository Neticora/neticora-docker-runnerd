//go:build linux

package katalinux

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"golang.org/x/sys/unix"
)

// A request budget, not a lifetime size limit. Durable filesystem progress and
// the original captured directory identity allow the next cleanup-only retry.
var errSandboxCleanupPending = errors.New("sandbox cleanup request budget exhausted; retain allocation and retry")
var errSandboxReferenceHeld = errors.New("sandbox inode or device still referenced")

func sandboxReferenceHeld() error { return errors.Join(ErrQualification, errSandboxReferenceHeld) }

func openSandboxParent(anchor, path string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || (path != anchor && !strings.HasPrefix(path, anchor+"/")) {
		return nil, ErrQualification
	}
	base, err := hostfs.OpenState(anchor)
	if err != nil {
		return nil, ErrQualification
	}
	defer base.Close()
	relative, err := filepath.Rel(anchor, path)
	if err != nil {
		return nil, ErrQualification
	}
	current := "."
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := base.Lstat(current)
		if err != nil {
			return nil, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		// Kata creates shared runtime subdirectories as 0777. They remain
		// behind this root-owned 0700 filesystem anchor. Never repair their
		// permissions or follow an alternate symlink path.
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || st.Uid != 0 {
			return nil, ErrQualification
		}
	}
	return base.OpenRoot(relative)
}

func sandboxStamp(anchor, root, id string) (SandboxDirectory, error) {
	if _, err := hex.DecodeString(id); len(id) != 64 || err != nil {
		return SandboxDirectory{}, ErrQualification
	}
	parent, err := openSandboxParent(anchor, root)
	if err != nil {
		return SandboxDirectory{}, err
	}
	defer parent.Close()
	info, err := parent.Lstat(id)
	if err != nil {
		return SandboxDirectory{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || st.Uid != 0 {
		return SandboxDirectory{}, ErrQualification
	}
	return SandboxDirectory{Root: root, Device: uint64(st.Dev), Inode: st.Ino}, nil
}

func (p *Profile) captureSandboxDirectories(id string) ([]SandboxDirectory, error) {
	if p.Manifest.Version != MultiBlockVersion {
		return nil, nil
	}
	var out []SandboxDirectory
	seen := map[string]bool{}
	for _, root := range p.Manifest.SandboxRoots {
		if seen[root] {
			continue
		}
		seen[root] = true
		stamp, err := sandboxStamp(p.Manifest.Storage.Runtime.Root, root, id)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || stamp.Device != p.Manifest.Storage.Runtime.Device {
			return nil, ErrQualification
		}
		out = append(out, stamp)
	}
	if len(out) == 0 {
		return nil, ErrQualification
	}
	return out, nil
}

// Runtime residue can outlive an OOM-killed shim. Cleanup is confined to a
// pre-crash captured directory inode, never a newly discovered matching name.
// Every destructive step rechecks the VM/peer guards and rejects references,
// mount points, symlinks, foreign ownership and filesystem crossings.
func (p *Profile) removeSandboxResidue(ctx context.Context, id string, directories []SandboxDirectory, guard func() error) error {
	ctx = context.WithValue(ctx, procDecodeKey{}, &procDecoder{})
	allowed := map[string]bool{}
	for _, root := range p.Manifest.SandboxRoots {
		allowed[root] = true
	}
	seen := map[string]bool{}
	for _, expected := range directories {
		if !allowed[expected.Root] || seen[expected.Root] || expected.Device == 0 || expected.Inode == 0 {
			return ErrQualification
		}
		seen[expected.Root] = true
		if err := sandboxTimed(ctx, "guard", guard); err != nil {
			return err
		}
		actual, err := sandboxStamp(p.Manifest.Storage.Runtime.Root, expected.Root, id)
		if errors.Is(err, os.ErrNotExist) {
			filesystemPath, e := sandboxFilesystemPath(filepath.Join(expected.Root, id), expected.Device)
			if e != nil || noBlockUsers(ctx, BlockRecord{FileDevice: expected.Device, FileInode: expected.Inode}) != nil || noSandboxNamespaceReferences(ctx, expected.Device, expected.Inode, filesystemPath) != nil {
				return ErrQualification
			}
			// Retry after a lost removal response must also make directory
			// absence durable before allowing the CLEANED event to commit.
			root, e := openSandboxParent(p.Manifest.Storage.Runtime.Root, expected.Root)
			if e != nil {
				return ErrQualification
			}
			e = syncSandboxParent(root, id, expected.Device)
			root.Close()
			if e != nil {
				return e
			}
			continue
		}
		if err != nil || actual != expected {
			return ErrQualification
		}
		root, err := openSandboxParent(p.Manifest.Storage.Runtime.Root, expected.Root)
		if err != nil {
			return ErrQualification
		}
		left := 4096
		err = removeSandboxTree(ctx, root, id, expected.Device, expected.Inode, 0, &left, guard)
		root.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func removeSandboxTree(ctx context.Context, root *os.Root, name string, device, inode uint64, depth int, left *int, guard func() error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	sandboxVisit(ctx, depth)
	if depth > 32 {
		return ErrQualification
	}
	if *left <= 0 {
		return errors.Join(ErrQualification, errSandboxCleanupPending)
	}
	*left--
	metadataDone := sandboxMetadata(ctx)
	info, err := root.Lstat(name)
	metadataDone()
	if err != nil {
		return ErrQualification
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(st.Dev) != device || inode != 0 && st.Ino != inode || st.Uid != 0 || (!info.IsDir() && info.Mode().Perm()&0022 != 0) || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		return ErrQualification
	}
	if info.IsDir() {
		metadataDone = sandboxMetadata(ctx)
		f, err := root.Open(name)
		metadataDone()
		if err != nil {
			return ErrQualification
		}
		defer f.Close()
		for {
			metadataDone = sandboxMetadata(ctx)
			children, readErr := f.Readdirnames(64)
			metadataDone()
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return ErrQualification
			}
			for _, child := range children {
				if err := removeSandboxTree(ctx, root, filepath.Join(name, child), device, 0, depth+1, left, guard); err != nil {
					return err
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
		}
		// Our own directory enumeration descriptor must not manufacture a held
		// reference when this directory's fresh reference checks run below.
		if err := f.Close(); err != nil {
			return err
		}
	}
	if err := sandboxTimed(ctx, "guard", guard); err != nil {
		return err
	}
	path := filepath.Join(root.Name(), name)
	var filesystemPath string
	err = sandboxTimed(ctx, "filesystemPath", func() error {
		var e error
		filesystemPath, e = sandboxFilesystemPath(path, device)
		return e
	})
	if err != nil {
		return err
	}
	for _, check := range []struct {
		name string
		run  func() error
	}{
		{"nestedMounts", func() error { return noNestedMounts(path) }},
		{"blockUsers", func() error { return noBlockUsers(ctx, BlockRecord{FileDevice: device, FileInode: st.Ino}) }},
		{"namespaceReferences", func() error { return noSandboxNamespaceReferences(ctx, device, st.Ino, filesystemPath) }},
	} {
		if err := sandboxTimed(ctx, check.name, check.run); err != nil {
			return err
		}
	}
	metadataDone = sandboxMetadata(ctx)
	current, err := root.Lstat(name)
	metadataDone()
	if err != nil || !os.SameFile(info, current) {
		return ErrQualification
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := sandboxTimed(ctx, "remove", func() error { return root.Remove(name) }); err != nil {
		return err
	}
	return sandboxTimed(ctx, "fsync", func() error { return syncSandboxParent(root, name, device) })
}

func syncSandboxParent(root *os.Root, name string, device uint64) error {
	f, err := root.Open(filepath.Dir(name))
	if err != nil {
		return ErrQualification
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return ErrQualification
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || uint64(st.Dev) != device {
		return ErrQualification
	}
	return f.Sync()
}

// A surviving thread may retain an independent mount namespace or cwd/root
// after its leader exits. Inspect every task, as with block reference checks.
func noSandboxNamespaceReferences(ctx context.Context, device, inode uint64, filesystemPath string) error {
	sandboxCount(ctx, "namespaceProcEnumeration")
	processes, err := os.ReadDir("/proc")
	if err != nil {
		return ErrQualification
	}
	for _, process := range processes {
		if _, err := strconv.Atoi(process.Name()); err != nil {
			continue
		}
		tasks, err := readProcessTasksIn(ctx, os.DirFS("/proc"), process.Name())
		if err != nil {
			return err
		}
		for _, task := range tasks {
			sandboxCount(ctx, "namespaceTask")
			base := filepath.Join("/proc", process.Name(), "task", task.Name())
			state, stateErr := os.ReadFile(filepath.Join(base, "stat"))
			if errors.Is(stateErr, os.ErrNotExist) {
				continue
			}
			close := strings.LastIndexByte(string(state), ')')
			if stateErr != nil || close < 0 {
				return ErrQualification
			}
			var status [1]string
			if procPrefixFields(string(state[close+1:]), status[:]) < len(status) {
				return ErrQualification
			}
			// A dead task has dropped its fs/nsproxy references. Surviving
			// threads are still inspected independently, even with a dead leader.
			if status[0] == "Z" || status[0] == "X" {
				continue
			}
			check := func(path string) error {
				var st syscall.Stat_t
				err := syscall.Stat(path, &st)
				if errors.Is(err, os.ErrNotExist) {
					return nil
				}
				if err != nil {
					return ErrQualification
				}
				if uint64(st.Dev) == device && st.Ino == inode {
					return sandboxReferenceHeld()
				}
				return nil
			}
			for _, field := range []string{"cwd", "root"} {
				if err := check(filepath.Join(base, field)); err != nil {
					return err
				}
			}
			sandboxCount(ctx, "mountinfoRead")
			raw, release, err := readProcCurrent(ctx, filepath.Join(base, "mountinfo"), 0)
			if errors.Is(err, os.ErrNotExist) {
				if _, e := os.Stat(base); errors.Is(e, os.ErrNotExist) {
					release()
					continue
				}
			}
			if err != nil {
				release()
				return ErrQualification
			}
			mounts, err := decodedMounts(ctx, raw)
			release()
			if err != nil {
				return err
			}
			for _, mount := range mounts {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				mountDevice, mountRoot := mount.Device, mount.Root
				// Inspect mount roots as well as visible mountpoints: a later
				// overmount can hide an earlier bind that still holds the inode.
				if filesystemPath != "" && mountDevice == device && (mountRoot == filesystemPath || strings.HasPrefix(mountRoot, filesystemPath+"/")) {
					return sandboxReferenceHeld()
				}
				point := mount.Point
				sandboxCount(ctx, "mountPointStat")
				if err := check(filepath.Join(base, "root", point)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func decodeSandboxMountPath(path string) string {
	if !strings.ContainsRune(path, '\\') {
		return path
	}
	return sandboxMountEscapes.Replace(path)
}

func sandboxMountDevice(value string) (uint64, error) {
	majorText, minorText, ok := strings.Cut(value, ":")
	if !ok {
		return 0, ErrQualification
	}
	major, e1 := strconv.ParseUint(majorText, 10, 32)
	minor, e2 := strconv.ParseUint(minorText, 10, 32)
	if e1 != nil || e2 != nil {
		return 0, ErrQualification
	}
	return unix.Mkdev(uint32(major), uint32(minor)), nil
}

func sandboxFilesystemPath(path string, device uint64) (string, error) {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", ErrQualification
	}
	longest, result := "", ""
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		var fields [6]string
		if procPrefixFields(line, fields[:]) < len(fields) {
			return "", ErrQualification
		}
		dev, err := sandboxMountDevice(fields[2])
		if err != nil {
			return "", err
		}
		point := decodeSandboxMountPath(fields[4])
		if dev != device || (path != point && !strings.HasPrefix(path, strings.TrimSuffix(point, "/")+"/")) || len(point) <= len(longest) {
			continue
		}
		relative, err := filepath.Rel(point, path)
		if err != nil {
			return "", ErrQualification
		}
		longest, result = point, filepath.Join(decodeSandboxMountPath(fields[3]), relative)
	}
	if longest == "" || !filepath.IsAbs(result) {
		return "", ErrQualification
	}
	return result, nil
}
