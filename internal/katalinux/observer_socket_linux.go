//go:build linux

package katalinux

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Called only while holding the exclusive observer lifecycle lock, after the
// listener parent has been verified root-owned and protected. SIGKILL cannot
// unlink a Unix listener. Never replace a live socket, symlink or foreign file.
func removeStaleObserverSocket(ctx context.Context, path string, uid int) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || before.Mode().Type() != os.ModeSocket || before.Mode().Perm() != 0600 {
		return ErrQualification
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(uid) || owner.Nlink != 1 {
		return ErrQualification
	}
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
	if err == nil {
		connection.Close()
		return ErrQualification
	}
	if !errors.Is(err, syscall.ECONNREFUSED) || ctx.Err() != nil {
		return ErrQualification
	}
	after, err := root.Lstat(name)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return ErrQualification
	}
	return root.Remove(name)
}
