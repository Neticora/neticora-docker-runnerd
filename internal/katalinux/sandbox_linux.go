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

func sandboxStamp(root, id string) (SandboxDirectory, error) {
	if _, err := hex.DecodeString(id); len(id) != 64 || err != nil || hostfs.CheckAncestors(root) != nil {
		return SandboxDirectory{}, ErrQualification
	}
	info, err := os.Lstat(filepath.Join(root, id))
	if err != nil {
		return SandboxDirectory{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
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
		stamp, err := sandboxStamp(root, id)
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
		if err := guard(); err != nil {
			return err
		}
		actual, err := sandboxStamp(expected.Root, id)
		if errors.Is(err, os.ErrNotExist) {
			filesystemPath, e := sandboxFilesystemPath(filepath.Join(expected.Root, id), expected.Device)
			if e != nil || noBlockUsers(ctx, BlockRecord{FileDevice: expected.Device, FileInode: expected.Inode}) != nil || noSandboxNamespaceReferences(ctx, expected.Device, expected.Inode, filesystemPath) != nil {
				return ErrQualification
			}
			// Retry after a lost removal response must also make directory
			// absence durable before allowing the CLEANED event to commit.
			root, e := os.OpenRoot(expected.Root)
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
		root, err := os.OpenRoot(expected.Root)
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
	if depth > 32 || *left <= 0 {
		return ErrQualification
	}
	*left--
	info, err := root.Lstat(name)
	if err != nil {
		return ErrQualification
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(st.Dev) != device || inode != 0 && st.Ino != inode || st.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		return ErrQualification
	}
	if info.IsDir() {
		f, err := root.Open(name)
		if err != nil {
			return ErrQualification
		}
		children, err := f.Readdirnames(4097)
		f.Close()
		if err != nil && !errors.Is(err, io.EOF) || len(children) > 4096 {
			return ErrQualification
		}
		for _, child := range children {
			if err := removeSandboxTree(ctx, root, filepath.Join(name, child), device, 0, depth+1, left, guard); err != nil {
				return err
			}
		}
	}
	if err := guard(); err != nil {
		return err
	}
	path := filepath.Join(root.Name(), name)
	filesystemPath, err := sandboxFilesystemPath(path, device)
	if err != nil || noNestedMounts(path) != nil || noBlockUsers(ctx, BlockRecord{FileDevice: device, FileInode: st.Ino}) != nil || noSandboxNamespaceReferences(ctx, device, st.Ino, filesystemPath) != nil {
		return ErrQualification
	}
	current, err := root.Lstat(name)
	if err != nil || !os.SameFile(info, current) {
		return ErrQualification
	}
	if err := root.Remove(name); err != nil {
		return err
	}
	return syncSandboxParent(root, name, device)
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
			base := filepath.Join("/proc", process.Name(), "task", task.Name())
			state, stateErr := os.ReadFile(filepath.Join(base, "stat"))
			if errors.Is(stateErr, os.ErrNotExist) {
				continue
			}
			close := strings.LastIndexByte(string(state), ')')
			if stateErr != nil || close < 0 {
				return ErrQualification
			}
			status := strings.Fields(string(state[close+1:]))
			if len(status) < 1 {
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
				if err != nil || uint64(st.Dev) == device && st.Ino == inode {
					return ErrQualification
				}
				return nil
			}
			for _, field := range []string{"cwd", "root"} {
				if err := check(filepath.Join(base, field)); err != nil {
					return err
				}
			}
			raw, err := os.ReadFile(filepath.Join(base, "mountinfo"))
			if errors.Is(err, os.ErrNotExist) {
				if _, e := os.Stat(base); errors.Is(e, os.ErrNotExist) {
					continue
				}
			}
			if err != nil {
				return ErrQualification
			}
			for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				fields := strings.Fields(line)
				if len(fields) < 6 {
					return ErrQualification
				}
				mountDevice, err := sandboxMountDevice(fields[2])
				if err != nil {
					return err
				}
				mountRoot := decodeSandboxMountPath(fields[3])
				// Inspect mount roots as well as visible mountpoints: a later
				// overmount can hide an earlier bind that still holds the inode.
				if filesystemPath != "" && mountDevice == device && (mountRoot == filesystemPath || strings.HasPrefix(mountRoot, filesystemPath+"/")) {
					return ErrQualification
				}
				point := decodeSandboxMountPath(fields[4])
				if !filepath.IsAbs(point) || strings.Contains(point, "..") {
					return ErrQualification
				}
				if err := check(filepath.Join(base, "root", point)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func decodeSandboxMountPath(path string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, "\\").Replace(path)
}

func sandboxMountDevice(value string) (uint64, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return 0, ErrQualification
	}
	major, e1 := strconv.ParseUint(parts[0], 10, 32)
	minor, e2 := strconv.ParseUint(parts[1], 10, 32)
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
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
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
