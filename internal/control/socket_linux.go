//go:build linux

package control

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

// socketListener holds the directory and inode we created. Disable net's default
// pathname unlink: cleanup must preserve any replacement file, symlink or socket.
// The parent is service-owned and not writable by other unprivileged users.
type socketListener struct {
	*net.UnixListener
	directory  *os.Root
	name       string
	identity   os.FileInfo
	once       sync.Once
	closeError error
}

func listenSocket(path string) (*socketListener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid control path")
	}
	parent := filepath.Dir(path)
	if err := hostfs.CheckAncestors(parent); err != nil {
		return nil, err
	}
	directory, err := os.OpenRoot(parent)
	if err != nil {
		return nil, errors.New("cannot open control directory")
	}
	keep := false
	defer func() {
		if !keep {
			_ = directory.Close()
		}
	}()
	info, err := directory.Stat(".")
	if err != nil || !info.IsDir() || info.Mode().Perm()&0027 != 0 {
		return nil, errors.New("unsafe control directory")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return nil, errors.New("unsafe control directory owner")
	}
	name := filepath.Base(path)
	if _, err = directory.Lstat(name); !os.IsNotExist(err) {
		return nil, errors.New("control path already exists or cannot be inspected")
	}
	raw, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, errors.New("cannot bind control socket")
	}
	raw.SetUnlinkOnClose(false)
	identity, err := directory.Lstat(name)
	if err != nil || identity.Mode()&os.ModeSocket == 0 {
		_ = raw.Close()
		return nil, errors.New("cannot establish control socket ownership")
	}
	owner, ok := identity.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() {
		_ = raw.Close()
		return nil, errors.New("unsafe control socket owner")
	}
	listener := &socketListener{UnixListener: raw, directory: directory, name: name, identity: identity}
	keep = true
	if err = directory.Chmod(name, 0660); err != nil {
		_ = listener.Close()
		return nil, errors.New("cannot protect control socket")
	}
	return listener, nil
}

func (s *socketListener) Close() error {
	s.once.Do(func() {
		defer s.directory.Close()
		closeErr := s.UnixListener.Close()
		current, err := s.directory.Lstat(s.name)
		switch {
		case os.IsNotExist(err):
			// A missing pathname needs no cleanup; never search for or remove another.
		case err != nil:
			s.closeError = errors.New("cannot inspect control socket for cleanup")
		default:
			originalOwner := s.identity.Sys().(*syscall.Stat_t).Uid
			owner, ok := current.Sys().(*syscall.Stat_t)
			if !ok || owner.Uid != originalOwner || current.Mode()&os.ModeSocket == 0 || !os.SameFile(s.identity, current) {
				s.closeError = errors.New("control socket identity changed; path preserved")
			} else if err = s.directory.Remove(s.name); err != nil {
				s.closeError = errors.New("cannot remove owned control socket")
			}
		}
		if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			s.closeError = errors.Join(s.closeError, errors.New("cannot close control listener"))
		}
	})
	return s.closeError
}
