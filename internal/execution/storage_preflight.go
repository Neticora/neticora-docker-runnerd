package execution

import (
	"context"
	"errors"
	"strings"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

var ErrKataOnly = errors.New("standalone Docker/Kata is required for workload execution")

func (c *Controller) StorageReady() bool {
	state := c.storageStatus.Load()
	return state == nil || state.(string) == ""
}

func (c *Controller) checkStorage(ctx context.Context) error {
	if c.Kata == nil || !c.Kata.Manifest.Standalone {
		return nil
	}
	id, err := c.Store.StorageJournalID(ctx)
	if err != nil || id != c.Kata.StorageJournalID {
		return errors.New("execution storage journal identity changed; restore the original journal before admission")
	}
	return c.Kata.StoragePreflight()
}

func (c *Controller) checkAdmissionStorage(ctx context.Context) error {
	err := c.checkStorage(ctx)
	if err == nil && c.Kata != nil && c.Kata.Manifest.Qualified {
		engine := kataRuntimeEngine(c.Runtime)
		if engine == nil {
			err = ErrKataOnly
		} else {
			err = c.Kata.Probe(ctx, engine)
			if err == nil && c.cache != nil {
				if _, poolErr := c.cache.lvm.Headroom(ctx, c.HostLimits.Slots); poolErr != nil {
					err = errors.New("configured LVM Thin pool identity or status unavailable")
				}
			}
		}
	}
	return err
}

func (c *Controller) reportStorageReady(ctx context.Context) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.checkAdmissionStorage(ctx)
	if err != nil {
		c.storageStatus.Store(err.Error())
		return false
	}
	c.storageStatus.Store("")
	return true
}

func (c *Controller) verifyUnallocated(ctx context.Context, e agent.Execution, p dockerengine.Plan) error {
	if c.cache == nil || c.Kata == nil || len(e.RuntimeRef) != 0 || len(e.StartRequest) != 0 || e.State != "accepted" || e.LastSequence != "0" || len(p.Name) != 68 || !strings.HasPrefix(p.Name, "nrd-") {
		return ErrReconcile
	}
	if _, exists, err := c.Store.KataCacheAttempt(ctx, executionKey(e)); err != nil || exists {
		return errors.Join(ErrReconcile, err)
	}
	if err := c.cache.lvm.VerifyAbsent(ctx, cacheVolumeName(p)); err != nil {
		return err
	}
	return c.Kata.VerifyUnallocated(ctx, p)
}
