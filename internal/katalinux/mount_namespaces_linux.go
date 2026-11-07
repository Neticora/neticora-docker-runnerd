//go:build linux

package katalinux

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type namespaceIdentity struct {
	device uint64
	inode  uint64
}

// Inspect every observable task's mount namespace without changing the observer's
// namespace. A namespace retained only by an FD or an nsfs bind mount cannot
// be inspected through a live task's mountinfo. Such orphaned mount namespaces
// are outside the supported host boundary: refuse release, never assume empty.
// Deferred loop-reference checks remain an independent release condition.
func loopMounted(ctx context.Context, dev uint64) error { return loopMountedIn(ctx, "/proc", dev) }

func loopMountedIn(ctx context.Context, procRoot string, dev uint64) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return err
	}
	seen := map[namespaceIdentity]bool{}
	var pinned []namespaceIdentity
	var taskPaths []string
	want := strconv.FormatUint(uint64(unix.Major(dev)), 10) + ":" + strconv.FormatUint(uint64(unix.Minor(dev)), 10)
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		base := filepath.Join(procRoot, entry.Name(), "task")
		tasks, err := readProcessTasksIn(ctx, os.DirFS(procRoot), entry.Name())
		if err != nil {
			return err
		}
		for _, task := range tasks {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			path := filepath.Join(base, task.Name())
			taskPaths = append(taskPaths, path)
			ns, err := os.Open(filepath.Join(path, "ns/mnt"))
			if errors.Is(err, os.ErrNotExist) {
				if _, e := os.Stat(path); errors.Is(e, os.ErrNotExist) {
					continue
				}
			}
			if err != nil {
				return ErrQualification
			}
			var id unix.Stat_t
			if unix.Fstat(int(ns.Fd()), &id) != nil {
				ns.Close()
				return ErrQualification
			}
			identity := namespaceIdentity{uint64(id.Dev), id.Ino}
			// Do not deduplicate only by namespace inode: chrooted tasks can
			// expose different mountinfo views of the same mount namespace.
			f, err := os.Open(filepath.Join(path, "mountinfo"))
			if err != nil {
				ns.Close()
				if errors.Is(err, os.ErrNotExist) {
					if _, e := os.Stat(path); errors.Is(e, os.ErrNotExist) {
						continue
					}
				}
				return ErrQualification
			}
			raw, err := io.ReadAll(io.LimitReader(f, 64<<20+1))
			f.Close()
			var after unix.Stat_t
			statErr := unix.Stat(filepath.Join(path, "ns/mnt"), &after)
			ns.Close()
			if err != nil || len(raw) == 0 || len(raw) > 64<<20 || statErr != nil || uint64(after.Dev) != identity.device || after.Ino != identity.inode {
				return ErrQualification
			}
			for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 10 || !strings.Contains(line, " - ") {
					return ErrQualification
				}
				if fields[2] == want {
					return ErrQualification
				}
			}
			pins, err := pinnedMountNamespaces(ctx, path, raw)
			if err != nil {
				return err
			}
			// Opening a pinned handle must not silently cross a task namespace
			// transition after the mountinfo snapshot.
			if unix.Stat(filepath.Join(path, "ns/mnt"), &after) != nil || uint64(after.Dev) != identity.device || after.Ino != identity.inode {
				return ErrQualification
			}
			pinned = append(pinned, pins...)
			seen[identity] = true
		}
	}
	for _, identity := range pinned {
		if !seen[identity] {
			return ErrQualification
		}
	}
	// Inspect FD tables per task as well: a thread may have unshared its table.
	for _, task := range taskPaths {
		base := filepath.Join(task, "fd")
		fds, err := os.ReadDir(base)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return ErrQualification
		}
		for _, fd := range fds {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			path := filepath.Join(base, fd.Name())
			var fs unix.Statfs_t
			if err := unix.Statfs(path, &fs); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return ErrQualification
			}
			if fs.Type != unix.NSFS_MAGIC {
				continue
			}
			ns, err := os.Open(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return ErrQualification
			}
			kind, e := unix.IoctlRetInt(int(ns.Fd()), unix.NS_GET_NSTYPE)
			var id unix.Stat_t
			statErr := unix.Fstat(int(ns.Fd()), &id)
			ns.Close()
			if e != nil || statErr != nil {
				return ErrQualification
			}
			if kind == unix.CLONE_NEWNS && !seen[namespaceIdentity{uint64(id.Dev), id.Ino}] {
				return ErrQualification
			}
		}
	}
	if len(seen) == 0 {
		return ErrQualification
	}
	return nil
}

// A persistent nsfs bind mount can retain an otherwise unoccupied namespace.
// Inspect its actual kernel namespace type/identity through the observed task's
// root, including escaped mountpoints. Unreachable handles fail closed.
func pinnedMountNamespaces(ctx context.Context, task string, raw []byte) ([]namespaceIdentity, error) {
	var out []namespaceIdentity
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		left, right, ok := strings.Cut(line, " - ")
		fields, kind := strings.Fields(left), strings.Fields(right)
		if !ok || len(fields) < 6 || len(kind) < 3 {
			return nil, ErrQualification
		}
		if kind[0] != "nsfs" {
			continue
		}
		mount, err := mountinfoPath(fields[4])
		if err != nil {
			return nil, err
		}
		path := filepath.Join(task, "root", strings.TrimPrefix(mount, "/"))
		ns, err := os.Open(path)
		if err != nil {
			return nil, ErrQualification
		}
		var fs unix.Statfs_t
		var st unix.Stat_t
		fsErr := unix.Fstatfs(int(ns.Fd()), &fs)
		nsKind, kindErr := unix.IoctlRetInt(int(ns.Fd()), unix.NS_GET_NSTYPE)
		statErr := unix.Fstat(int(ns.Fd()), &st)
		ns.Close()
		if fsErr != nil || fs.Type != unix.NSFS_MAGIC || kindErr != nil || statErr != nil {
			return nil, ErrQualification
		}
		if nsKind == unix.CLONE_NEWNS {
			out = append(out, namespaceIdentity{uint64(st.Dev), st.Ino})
		}
	}
	return out, nil
}
func mountinfoPath(raw string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			out.WriteByte(raw[i])
			continue
		}
		if i+3 >= len(raw) {
			return "", ErrQualification
		}
		switch raw[i+1 : i+4] {
		case "040":
			out.WriteByte(' ')
		case "011":
			out.WriteByte('\t')
		case "012":
			out.WriteByte('\n')
		case "134":
			out.WriteByte('\\')
		default:
			return "", ErrQualification
		}
		i += 3
	}
	path := out.String()
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return "", ErrQualification
	}
	return path, nil
}
