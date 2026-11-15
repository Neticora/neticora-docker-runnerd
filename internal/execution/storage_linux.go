//go:build linux

package execution

import (
	"github.com/Neticora/neticora-docker-runnerd/internal/executionstorage"
	"syscall"
)

func volatileDirectory(path string) error {
	var fs syscall.Statfs_t
	if syscall.Statfs(path, &fs) != nil || uint64(fs.Type) != 0x01021994 {
		return ErrReconcile
	}
	return nil
}

func persistentDirectory(path string) error {
	var fs syscall.Statfs_t
	if syscall.Statfs(path, &fs) != nil {
		return ErrReconcile
	}
	switch uint64(fs.Type) {
	case 0xEF53, 0x58465342, 0x9123683E, 0xF2F52010:
		return nil
	}
	return ErrReconcile
}

func backingHeadroom(path string, minimum uint64) error {
	var fs syscall.Statfs_t
	if syscall.Statfs(path, &fs) != nil || fs.Bsize <= 0 || fs.Bavail > ^uint64(0)/uint64(fs.Bsize) {
		return executionstorage.ErrPressure
	}
	if fs.Bavail*uint64(fs.Bsize) < 64<<20 || fs.Ffree < 128 {
		return executionstorage.ErrCriticalPressure
	}
	if fs.Bavail*uint64(fs.Bsize) < minimum || fs.Ffree < 1024 {
		return executionstorage.ErrPressure
	}
	return nil
}
