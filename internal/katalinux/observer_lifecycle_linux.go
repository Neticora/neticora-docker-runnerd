//go:build linux

package katalinux

import (
	"errors"
	"os"
	"syscall"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"golang.org/x/sys/unix"
)

// The observer holds this inode lock from before binding its socket until every
// handler has stopped. Administrative reconciliation takes the same lock before
// looking at the socket or storage. Never unlink the lock or infer process death
// from a missing socket. A competing restart must require an explicit retry.
func lockObserverLifecycle(directory string) (*os.File, error) {
	root, err := hostfs.OpenState(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.OpenFile(".observer-lifecycle.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0777 != 0600 || st.Uid != 0 || st.Nlink != 1 || st.Size != 0 {
		f.Close()
		return nil, ErrQualification
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrObserverLifecycleBusy
		}
		return nil, err
	}
	if err = syncRoot(root); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
