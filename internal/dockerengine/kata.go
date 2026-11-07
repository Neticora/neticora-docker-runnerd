package dockerengine

import (
	"context"

	"github.com/moby/moby/client"
)

func (e *Engine) CheckKataTuple(ctx context.Context, selector, version, root, shim, runtimeConfig string, startupConfig ...string) error {
	if err := e.check(ctx); err != nil {
		return err
	}
	info, err := e.api.Info(ctx, client.InfoOptions{})
	if err != nil {
		return e.lost()
	}
	if info.Info.ServerVersion != version || info.Info.DockerRootDir != root || info.Info.Driver != "overlay2" || info.Info.LiveRestoreEnabled {
		return ErrConflict
	}
	configured, ok := info.Info.Runtimes[selector]
	if !ok {
		return ErrConflict
	}
	if configured.Type == "" && configured.Path == "" && len(configured.Args) == 0 && len(configured.Options) == 0 {
		if len(startupConfig) != 2 || e.verifyKataStartupConfig(ctx, selector, shim, runtimeConfig, startupConfig[0], startupConfig[1]) != nil {
			return ErrConflict
		}
	} else if configured.Type != shim || configured.Path != "" || len(configured.Args) != 0 || len(configured.Options) != 1 || configured.Options["ConfigPath"] != runtimeConfig {
		return ErrConflict
	}
	if err = checkQuotaFilesystem(root); err != nil {
		return err
	}
	return e.check(ctx)
}

// The customer bridge is retained. Only this execution's network endpoint must
// disappear; a name or missing outer container alone is insufficient.
func (e *Engine) VerifyNetworkDetached(ctx context.Context, id, network string) error {
	if err := e.check(ctx); err != nil {
		return err
	}
	r, err := e.api.NetworkInspect(ctx, network, client.NetworkInspectOptions{})
	if err != nil {
		return e.lost()
	}
	if r.Network.ID != network {
		return ErrConflict
	}
	if _, ok := r.Network.Containers[id]; ok {
		return ErrConflict
	}
	return e.check(ctx)
}
