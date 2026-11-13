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
// which survived exec necessarily had CLOEXEC clear. Standard streams are restricted to
// terminal/null, pipe, same-user files or the root system journal; resource
// descriptors cannot hide in stdio. No socket activation/FD store is supported.
func CheckBrokerEntryDescriptors() error {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		fd, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if errors.Is(e, unix.EBADF) {
			continue
		} // our closed enumeration descriptor
		if e != nil {
			return e
		}
		if fd < 3 {
			if e = checkBrokerStandardDescriptor(fd); e != nil {
				return e
			}
			continue
		}
		if flags&unix.FD_CLOEXEC == 0 {
			return fmt.Errorf("%w: inherited descriptor %d", ErrReconcile, fd)
		}
	}
	return nil
}

// systemd journal streams, pipes, an operator's own output file and ordinary
// terminals do not grant access to protected metadata or a privileged API.
// A socket in stdio must be the root system journal, never Docker/containerd.
func checkBrokerStandardDescriptor(fd int) error {
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil {
		return ErrReconcile
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_PATH != 0 {
		return fmt.Errorf("%w: privileged standard descriptor %d", ErrReconcile, fd)
	}
	allowed := false
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFIFO:
		allowed = true
	case unix.S_IFREG:
		allowed = stat.Uid == uint32(os.Geteuid())
	case unix.S_IFCHR:
		allowed = unix.Major(uint64(stat.Rdev)) == 1 && unix.Minor(uint64(stat.Rdev)) == 3
		if !allowed {
			_, err = unix.IoctlGetTermios(fd, unix.TCGETS)
			allowed = err == nil
		}
	case unix.S_IFSOCK:
		peer, e := unix.Getpeername(fd)
		address, ok := peer.(*unix.SockaddrUnix)
		if e == nil && ok && address.Name == "/run/systemd/journal/stdout" {
			credentials, e := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
			allowed = e == nil && credentials.Uid == 0
		}
	}
	if !allowed {
		return fmt.Errorf("%w: privileged standard descriptor %d", ErrReconcile, fd)
	}
	return nil
}
