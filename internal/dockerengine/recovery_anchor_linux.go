//go:build linux

package dockerengine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/moby/moby/client"
)

// RecoveryDomain is recorded BEFORE the original physical intent. A changed
// peer can be authorized after reboot only when this protected storage anchor
// still matches. Empty replacement engines and copied daemon IDs do not suffice.
func (e *Engine) RecoveryDomain(ctx context.Context) (string, error) {
	if err := e.check(ctx); err != nil {
		return "", err
	}
	info, err := e.api.Info(ctx, client.InfoOptions{})
	if err != nil {
		return "", e.lost()
	}
	path := info.Info.DockerRootDir
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || hostfs.CheckAncestors(path) != nil {
		return "", ErrConflict
	}
	stat, err := os.Lstat(path)
	if err != nil || !stat.IsDir() {
		return "", ErrConflict
	}
	st, ok := stat.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || stat.Mode().Perm()&0022 != 0 {
		return "", ErrConflict
	}
	var fs syscall.Statfs_t
	if syscall.Statfs(path, &fs) != nil {
		return "", ErrUnavailable
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("runnerd-docker-storage-v1\x00%s\x00%s\x00%d\x00%d\x00%v", info.Info.ID, path, st.Dev, st.Ino, fs.Fsid)))
	return hex.EncodeToString(sum[:]), e.check(ctx)
}

// Unknown create outcomes have no durable container ID. Verify the original
// deterministic name in the exact network as well as any recovered immutable ID.
func (e *Engine) VerifyRecoveryNetworkDetached(ctx context.Context, id, name, network string) error {
	if err := e.check(ctx); err != nil {
		return err
	}
	result, err := e.api.NetworkInspect(ctx, network, client.NetworkInspectOptions{})
	if err != nil {
		return e.lost()
	}
	if result.Network.ID != network {
		return ErrConflict
	}
	for attached, endpoint := range result.Network.Containers {
		if attached == id || endpoint.Name == name || endpoint.Name == "" {
			return ErrConflict
		}
	}
	return e.check(ctx)
}
