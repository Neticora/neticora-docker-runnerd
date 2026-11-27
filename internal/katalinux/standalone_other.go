//go:build !linux

package katalinux

import (
	"context"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

func (*Profile) ReleaseStandalone(context.Context, dockerengine.Plan) error  { return ErrQualification }
func (*Profile) VerifyStandaloneRuntimeAbsent(context.Context, string) error { return ErrQualification }

func (*Profile) StoragePreflight() error { return ErrQualification }

func (*Profile) VerifyUnallocated(context.Context, dockerengine.Plan) error { return ErrQualification }
func (*Profile) VerifyExecutionDevicesAbsent(context.Context, dockerengine.Plan) error {
	return ErrQualification
}
