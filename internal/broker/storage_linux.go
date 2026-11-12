//go:build linux

package broker

import (
	"os"
	"syscall"
)

func durableStorage(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	var stat syscall.Statfs_t
	if err = syscall.Fstatfs(int(f.Fd()), &stat); err != nil {
		return err
	}
	// Durable local filesystems only. No tmpfs/network/overlay qualification is
	// inferred from fsync succeeding on an ephemeral filesystem.
	switch uint64(stat.Type) {
	case 0xef53, 0x58465342, 0x9123683e, 0xf2f52010:
		return nil
	}
	return ErrRejected
}

func ownedRecord(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid() && (info.IsDir() || stat.Nlink == 1)
}
