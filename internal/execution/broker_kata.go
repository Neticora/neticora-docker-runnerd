package execution

import (
	"context"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"time"
)

type kataBrokerRuntime interface {
	KataHealthy(context.Context, string, dockerengine.Plan) bool
	KataPhysicalEvidence(context.Context, string, dockerengine.Plan) (katalinux.Evidence, error)
	VerifyKataAbsence(context.Context, string, dockerengine.Plan) error
}

func (c *Controller) brokerKata() bool { return c.Kata != nil && c.kataBroker != nil }
func (c *Controller) kataHealthy(ctx context.Context, p dockerengine.Plan, o dockerengine.Object) bool {
	if c.brokerKata() {
		return c.kataBroker.KataHealthy(ctx, o.ID, p)
	}
	return c.Kata.Healthy(p, o.StartedAt, time.Now())
}
func (c *Controller) kataPhysicalEvidence(ctx context.Context, id string, p dockerengine.Plan) (katalinux.Evidence, error) {
	if c.brokerKata() {
		return c.kataBroker.KataPhysicalEvidence(ctx, id, p)
	}
	return c.Kata.PhysicalEvidence(ctx, id, p)
}
func (c *Controller) verifyKataAbsence(ctx context.Context, id string, p dockerengine.Plan) error {
	if c.brokerKata() {
		return c.kataBroker.VerifyKataAbsence(ctx, id, p)
	}
	return verifyKataAbsence(ctx, c.Kata, c.Runtime, id, p)
}
