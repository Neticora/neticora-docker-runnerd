//go:build !linux

package execution

import (
	"context"

	"github.com/Neticora/neticora-docker-runnerd/internal/config"
)

func RecoverOnBoot(context.Context, config.Config, string, string) error { return ErrKataOnly }
