//go:build !linux

package katalinux

import (
	"context"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"time"
)

func (*Profile) Check(time.Time) error                                    { return ErrQualification }
func (*Profile) Prepare(dockerengine.Plan) error                          { return ErrQualification }
func (*Profile) Capture(context.Context, string, dockerengine.Plan) error { return ErrQualification }
func (*Profile) CapturePrepared(string, dockerengine.Plan) error          { return ErrQualification }
func (*Profile) VerifyAbsent(context.Context, string, dockerengine.Plan, ...func() error) error {
	return ErrQualification
}
func (*Profile) layout() error                                     { return ErrQualification }
func (*Profile) Healthy(dockerengine.Plan, string, time.Time) bool { return false }
func (*Profile) PrepareHealth(dockerengine.Plan) error             { return ErrQualification }
func (*Profile) CleanHealth(dockerengine.Plan)                     {}

func (*Profile) PhysicalEvidence(context.Context, string, dockerengine.Plan) (Evidence, error) {
	return Evidence{}, ErrQualification
}

func (*Profile) prepareBlock(context.Context, dockerengine.Plan) error  { return ErrQualification }
func (*Profile) VerifyStorage(context.Context, dockerengine.Plan) error { return ErrQualification }
