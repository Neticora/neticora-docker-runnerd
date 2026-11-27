package execution

import (
	"context"

	"github.com/Neticora/neticora-docker-runnerd/agent"
)

// CheckResume permits an explicit local resume only after all previous work is
// finalized and the original runtime is available. Platform admission, signed
// grants and broker launch guards remain independent prerequisites.
func (c *Controller) CheckResume(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.recoveryOnly || c.Policy == nil || c.Policy() == nil || c.Runtime == nil || c.Store == nil {
		return ErrReconcile
	}
	if !c.Store.Health(ctx).Ready {
		return ErrReconcile
	}
	rows, err := c.Store.Incomplete(ctx, agent.ExecutionCursor{}, 1)
	if err != nil || len(rows) != 0 {
		return ErrReconcile
	}
	endpoint, err := c.Runtime.Probe(ctx)
	if err != nil || endpoint != c.Scope.EndpointIdentity {
		return ErrReconcile
	}
	if err := c.checkAdmissionStorage(ctx); err != nil {
		return err
	}
	if c.resumeGuard != nil {
		return c.resumeGuard(ctx)
	}
	return ctx.Err()
}
