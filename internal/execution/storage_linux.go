//go:build linux

package execution

import "syscall"

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
