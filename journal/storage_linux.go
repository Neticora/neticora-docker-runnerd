//go:build linux

package journal

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func localStorage(path string) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return err
	}
	// Explicit local filesystem allowlist. Overlay is useful for disposable CI;
	// production qualification must use durable ext4/XFS/btrfs backing storage.
	switch uint64(st.Type) {
	case 0xef53, 0x58465342, 0x9123683e, 0xf2f52010, 0x794c7630:
		return nil
	default:
		return errors.New("recovery store requires supported local durable storage")
	}
}

func availableBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

func privateFile(path string, create bool) error {
	flags := syscall.O_RDWR | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
	if create {
		flags |= syscall.O_CREAT | syscall.O_EXCL
	}
	fd, err := syscall.Open(path, flags, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("unsafe recovery file ownership, links, type or permissions")
	}
	if create {
		if err = f.Sync(); err != nil {
			return err
		}
		return syncDirectory(filepath.Dir(path))
	}
	return nil
}
