//go:build !linux

package katalinux

import (
	"context"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

func (*Profile) remote(context.Context, string, string, dockerengine.Plan) error {
	return ErrQualification
}
func (*Profile) DiscardPrepared(context.Context, dockerengine.Plan) error { return ErrQualification }
func ServeObserver(context.Context, string) error                         { return ErrQualification }

func InstallStorageReconciliation(string, string, string) error { return ErrQualification }
