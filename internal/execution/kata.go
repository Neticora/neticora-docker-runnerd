package execution

import (
	"context"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
)

func (c *Controller) resolvePlan(scope agent.StoreScope, s protocol.ExecutionSpec) (dockerengine.Plan, error) {
	if s.IsolationProfile == "isolated" {
		if c.Kata == nil {
			return dockerengine.Plan{}, katalinux.ErrQualification
		}
		return c.Kata.Plan(scope, s)
	}
	if s.IsolationProfile != "standard" || c.Kata != nil {
		return dockerengine.Plan{}, katalinux.ErrQualification
	}
	return c.Profile.Plan(scope, s)
}

// Recovery reconstruction is used only for commands already in the store. A
// fresh launch must separately obtain a launch plan after current admission.
func (c *Controller) resolveRecoveryPlan(scope agent.StoreScope, s protocol.ExecutionSpec) (dockerengine.Plan, error) {
	if s.IsolationProfile == "isolated" {
		if c.Kata == nil {
			return dockerengine.Plan{}, katalinux.ErrQualification
		}
		return c.Kata.RecoveryPlan(scope, s)
	}
	if s.IsolationProfile != "standard" || c.Kata != nil {
		return dockerengine.Plan{}, katalinux.ErrQualification
	}
	return c.Profile.Plan(scope, s)
}
func (c *Controller) admit(s protocol.ExecutionSpec, now time.Time) error {
	if c.Kata != nil {
		if err := c.Kata.Admit(c.Scope, s, c.Policy(), now); err != nil {
			return err
		}
		runtime := kataRuntimeEngine(c.Runtime)
		if runtime == nil {
			return katalinux.ErrQualification
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return c.Kata.Probe(ctx, runtime)
	}
	return c.Policy().Admit(c.Scope, s, now)
}
func verifyKataAbsence(ctx context.Context, profile *katalinux.Profile, runtime any, id string, p dockerengine.Plan) error {
	if p.Config.Labels[dockerengine.LabelPrefix+"template"] != katalinux.Template && p.Config.Labels[dockerengine.LabelPrefix+"template"] != katalinux.BlockTemplate {
		return nil
	}
	if profile == nil {
		return katalinux.ErrQualification
	}
	net, ok := runtime.(interface {
		VerifyNetworkDetached(context.Context, string, string) error
	})
	if !ok {
		return katalinux.ErrQualification
	}
	if err := net.VerifyNetworkDetached(ctx, id, string(p.HostConfig.NetworkMode)); err != nil {
		return err
	}
	return profile.VerifyAbsent(ctx, id, p)
}
