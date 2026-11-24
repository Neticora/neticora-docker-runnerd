//go:build !linux

package katalinux

import (
	"context"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

func (*Profile) ReleaseStandalone(context.Context, dockerengine.Plan) error { return ErrQualification }
