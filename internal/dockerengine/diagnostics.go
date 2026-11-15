package dockerengine

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// These fixed, credential-free diagnostics also match ErrUnavailable. Callers
// must retain the installation and reconcile after any failed observation.
var (
	ErrSocketInaccessible = errors.New("Docker socket is inaccessible or missing; check the selected Unix endpoint and install/start Docker")
	ErrPermission         = errors.New("Docker socket permission denied for the effective Runnerd account; an administrator must explicitly authorize its access before retrying setup")
	ErrDaemonUnavailable  = errors.New("Docker daemon is unavailable or did not answer; inspect Docker service health")
	ErrUnsupported        = errors.New("unsupported Docker configuration; use a local root-owned Linux Docker Engine Unix socket, directly bound or systemd-activated")
	ErrContinuity         = errors.New("Docker daemon or socket continuity changed; preserve original state and use authorized reconciliation/recovery")
)

func diagnostic(err error) error {
	for _, category := range []error{ErrPermission, ErrSocketInaccessible, ErrUnsupported, ErrContinuity, ErrDaemonUnavailable} {
		if errors.Is(err, category) {
			return fmt.Errorf("%w: %w", ErrUnavailable, category)
		}
	}
	switch {
	case errors.Is(err, os.ErrPermission), errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return fmt.Errorf("%w: %w", ErrUnavailable, ErrPermission)
	case errors.Is(err, os.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		return fmt.Errorf("%w: %w", ErrUnavailable, ErrSocketInaccessible)
	default:
		return fmt.Errorf("%w: %w", ErrUnavailable, ErrDaemonUnavailable)
	}
}

func (e *Engine) unavailable(err error) error {
	if e.invalidated != nil {
		e.invalidated()
	}
	return diagnostic(err)
}
