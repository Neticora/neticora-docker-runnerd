//go:build linux

package katalinux

import (
	"context"
	"errors"
	"os"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

// ReleaseStandalone releases the journal-owned raw disk and cgroup after the
// direct engine has removed the exact container. Loop and device claims are
// reconciled by the same allocator used at launch.
func (p *Profile) ReleaseStandalone(ctx context.Context, plan dockerengine.Plan) error {
	if !p.Manifest.Standalone || p.Manifest.Storage.Block == nil || p.ObserverSocket != "" || os.Geteuid() != 0 || !ownedName(plan.Name) {
		return ErrQualification
	}
	if _, err := p.releaseHostCgroup(ctx, plan); err != nil {
		return err
	}
	if _, err := p.blockRecord(plan); err == nil {
		if err = p.releaseBlock(ctx, plan); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
