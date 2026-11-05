//go:build linux

package dockerengine

import "syscall"

func storageAvailable(path string) (uint64, error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return 0, err
	}
	if fs.Bsize <= 0 || fs.Bavail > ^uint64(0)/uint64(fs.Bsize) {
		return 0, ErrStoragePressure
	}
	return fs.Bavail * uint64(fs.Bsize), nil
}
