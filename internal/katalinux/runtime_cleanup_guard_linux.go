//go:build linux

package katalinux

import (
	"context"
	"errors"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

// This is the observer's live guard, also exercised by the opt-in stress test.
// A missing object alone does not establish network or daemon-peer continuity.
func runtimeCleanupGuard(ctx context.Context, engine *dockerengine.Engine, id string, plan dockerengine.Plan, network, expectedEndpoint string) func() error {
	return func() error {
		_, err := engine.Inspect(ctx, id, plan)
		if !errors.Is(err, dockerengine.ErrAbsent) {
			return ErrQualification
		}
		if err = engine.VerifyNetworkDetached(ctx, id, network); err != nil {
			return err
		}
		endpoint, err := engine.Probe(ctx)
		if err != nil || endpoint != expectedEndpoint {
			return ErrQualification
		}
		return nil
	}
}
