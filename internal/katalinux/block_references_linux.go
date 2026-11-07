//go:build linux

package katalinux

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func blockReference(st syscall.Stat_t, r BlockRecord) bool {
	return (r.FileInode != 0 && uint64(st.Dev) == r.FileDevice && st.Ino == r.FileInode) ||
		(r.LoopDevice != 0 && st.Mode&syscall.S_IFMT == syscall.S_IFBLK && uint64(st.Rdev) == r.LoopDevice)
}

// A closed descriptor does not release mmap's reference to its inode, even
// after unlink. Compare maps by numeric device/inode, never pathname suffixes;
// map_files additionally identifies mappings of block nodes by their rdev.
func noMappedBlockUsers(ctx context.Context, task string, r BlockRecord) error {
	f, err := os.Open(filepath.Join(task, "maps"))
	if errors.Is(err, os.ErrNotExist) {
		if _, e := os.Stat(task); errors.Is(e, os.ErrNotExist) {
			return nil
		}
	}
	if err != nil {
		return ErrQualification
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			return ErrQualification
		}
		inode, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil {
			return ErrQualification
		}
		device := strings.Split(fields[3], ":")
		if len(device) != 2 {
			return ErrQualification
		}
		major, e1 := strconv.ParseUint(device[0], 16, 32)
		minor, e2 := strconv.ParseUint(device[1], 16, 32)
		if e1 != nil || e2 != nil {
			return ErrQualification
		}
		if inode != 0 && inode == r.FileInode && unix.Mkdev(uint32(major), uint32(minor)) == r.FileDevice {
			return ErrQualification
		}
		if inode == 0 || r.LoopDevice == 0 {
			continue
		}
		address := strings.Split(fields[0], "-")
		if len(address) != 2 {
			return ErrQualification
		}
		start, e1 := strconv.ParseUint(address[0], 16, 64)
		end, e2 := strconv.ParseUint(address[1], 16, 64)
		if e1 != nil || e2 != nil || end <= start {
			return ErrQualification
		}
		var st syscall.Stat_t
		err = syscall.Stat(filepath.Join(task, "map_files", fields[0]), &st)
		// The mapping may disappear while observed. Other read failures are not
		// proof that its reference is absent and must hold the reservation.
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return ErrQualification
		}
		if blockReference(st, r) {
			return ErrQualification
		}
	}
	if scanner.Err() != nil {
		return ErrQualification
	}
	return nil
}

func noTaskBlockUsers(ctx context.Context, task string, r BlockRecord) error {
	if err := noMappedBlockUsers(ctx, task, r); err != nil {
		return err
	}
	fds, err := os.ReadDir(filepath.Join(task, "fd"))
	if errors.Is(err, os.ErrNotExist) {
		if _, e := os.Stat(task); errors.Is(e, os.ErrNotExist) {
			return nil
		}
	}
	if err != nil {
		return ErrQualification
	}
	for _, fd := range fds {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var st syscall.Stat_t
		err = syscall.Stat(filepath.Join(task, "fd", fd.Name()), &st)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return ErrQualification
		}
		if blockReference(st, r) {
			return ErrQualification
		}
	}
	return nil
}

// Include every task: its FD table may have been unshared, and the thread-group
// leader can exit before its surviving threads. The observer is included too.
func noBlockUsers(ctx context.Context, r BlockRecord) error { return noBlockUsersIn(ctx, "/proc", r) }

func noBlockUsersIn(ctx context.Context, procRoot string, r BlockRecord) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		base := filepath.Join(procRoot, entry.Name(), "task")
		tasks, err := readProcessTasksIn(ctx, os.DirFS(procRoot), entry.Name())
		if err != nil {
			return err
		}
		for _, task := range tasks {
			if err := noTaskBlockUsers(ctx, filepath.Join(base, task.Name()), r); err != nil {
				return err
			}
		}
	}
	return nil
}
