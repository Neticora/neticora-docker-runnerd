//go:build !linux

package katalinux

import (
	"context"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

func (*Profile) prepareHostCgroup(context.Context, dockerengine.Plan) error {
	return ErrQualification
}

func (*Profile) verifyHostCgroup(context.Context, dockerengine.Plan, []Process) (*CgroupRecord, error) {
	return nil, ErrQualification
}

func (*Profile) releaseHostCgroup(context.Context, dockerengine.Plan) (*CgroupRecord, error) {
	return nil, ErrQualification
}
