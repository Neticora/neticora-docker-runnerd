//go:build linux

package hostfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func secureStat(info os.FileInfo, dir bool) error {
	return secureStatOwner(info, dir, os.Geteuid())
}

func secureStatOwner(info os.FileInfo, dir bool, uid int) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != uid || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe local file ownership or permissions")
	}
	if dir != info.IsDir() || (!dir && !info.Mode().IsRegular()) {
		return errors.New("unsafe local file type")
	}
	return nil
}

func ReadPrivate(path string, limit int64) ([]byte, error) {
	return readPrivate(path, limit, os.Geteuid())
}

func ReadGuestFile(path string, limit int64, uid int) ([]byte, error) {
	if os.Geteuid() != 0 || uid <= 0 {
		return nil, errors.New("invalid guest file owner")
	}
	return readPrivate(path, limit, uid)
}

func readPrivate(path string, limit int64, uid int) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || limit < 0 {
		return nil, errors.New("invalid protected file path or limit")
	}
	dir := filepath.Dir(path)
	if uid != os.Geteuid() {
		root, err := OpenGuestDirectory(dir, uid, false)
		if err != nil {
			return nil, err
		}
		root.Close()
		dir = filepath.Dir(dir)
	}
	if err := CheckAncestors(dir); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open protected local file")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errors.New("cannot inspect protected file")
	}
	if err = secureStatOwner(info, false, uid); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("protected file unreadable or oversized")
	}
	return data, nil
}

// Installation uses a dedicated service-owned directory. Symlink components
// are rejected before opening a confined root used for all state operations.
func OpenState(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid state path")
	}
	if err := CheckAncestors(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err = secureStat(info, true); err != nil {
		return nil, err
	}
	return os.OpenRoot(path)
}

// OpenGuestDirectory grants the guest UID control of only one directory
// under a host-owned parent. Root retains its separate host-private state.
func OpenGuestDirectory(path string, uid int, create bool) (*os.Root, error) {
	if os.Geteuid() != 0 || uid <= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid guest directory")
	}
	parent, err := OpenState(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	name := filepath.Base(path)
	if create {
		if err = parent.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	info, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if create && secureStat(info, true) == nil {
		// Root can retry a mkdir whose chown was interrupted before publication.
		if err = parent.Chown(name, uid, uid); err != nil {
			return nil, err
		}
		info, err = parent.Lstat(name)
		if err != nil {
			return nil, err
		}
	}
	if err = secureStatOwner(info, true, uid); err != nil {
		return nil, err
	}
	return parent.OpenRoot(name)
}

// CheckAncestors rejects symlink or untrusted writable directory components.
func CheckAncestors(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("invalid protected directory path")
	}
	current := string(filepath.Separator)
	for _, part := range splitPath(path) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return errors.New("state directory must be provisioned before startup")
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe state directory")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) || (info.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0)) {
			return errors.New("unsafe state ancestor ownership or permissions")
		}
	}
	return nil
}

func splitPath(path string) []string {
	var parts []string
	for path != "/" && path != "." {
		parts = append([]string{filepath.Base(path)}, parts...)
		path = filepath.Dir(path)
	}
	return parts
}

// Lock is advisory and retained by its file descriptor. Never unlink a lock
// file on shutdown: replacement would permit a second process to lock a new inode.
func Lock(root *os.Root) (*os.File, error) {
	f, err := root.OpenFile("instance.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("cannot open instance lock")
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if err = secureStat(info, false); err != nil {
		f.Close()
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another process owns this installation")
	}
	return f, nil
}
