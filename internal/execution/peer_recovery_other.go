//go:build !linux

package execution

import (
	"context"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
)

func actualBootID() (string, error) { return "", ErrReconcile }
func AdministrativePeerRecovery(context.Context, config.Config, string, string, string) ([]byte, error) {
	return nil, ErrReconcile
}
