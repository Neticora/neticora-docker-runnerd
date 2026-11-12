package dockerengine

import (
	"context"
	"github.com/moby/moby/client"
)

// CheckIsolatedNetwork verifies an already provisioned, exact operator network.
// The engine never creates a bridge or changes customer network policy.
func (e *Engine) CheckIsolatedNetwork(ctx context.Context, id, bridge string, ipv6 bool) error {
	if err := e.check(ctx); err != nil {
		return err
	}
	r, err := e.api.NetworkInspect(ctx, id, client.NetworkInspectOptions{})
	if err != nil {
		return e.lost()
	}
	n := r.Network
	if n.ID != id || n.Driver != "bridge" || n.Scope != "local" || n.Internal || n.Ingress || n.EnableIPv6 != ipv6 || n.Options["com.docker.network.bridge.name"] != bridge || n.Options["com.docker.network.bridge.enable_icc"] != "false" {
		return ErrConflict
	}
	return e.check(ctx)
}
