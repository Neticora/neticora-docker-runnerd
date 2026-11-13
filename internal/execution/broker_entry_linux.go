//go:build linux

package execution

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// CheckBrokerEntryDescriptors runs at executable entry, before signals, journal,
// transport or control sockets are opened. An inherited O_PATH/directory FD can
// bypass a root-private ancestor just as an inherited Docker socket can bypass
// its pathname permissions. Go-created descriptors are CLOEXEC; a descriptor
// which survived exec necessarily had CLOEXEC clear. Standard streams are the
// installed service's trusted journal/stdio boundary and are checked separately
// by installed-service qualification. No socket activation/FD store is supported.
func CheckBrokerEntryDescriptors() error {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		fd, e := strconv.Atoi(entry.Name())
		if e != nil || fd < 3 {
			continue
		}
		flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if errors.Is(e, unix.EBADF) {
			continue
		} // our closed enumeration descriptor
		if e != nil {
			return e
		}
		if flags&unix.FD_CLOEXEC == 0 {
			return fmt.Errorf("%w: inherited descriptor %d", ErrReconcile, fd)
		}
	}
	return nil
}
