package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/stickycache"
	"github.com/Neticora/neticora-docker-runnerd/journal"
	"github.com/moby/moby/api/types/container"
)

type kataCache struct {
	lvm       stickycache.LVM
	key       string
	legacyKey string
}

type cacheOutcomeRemote interface {
	KataCacheDecision(context.Context, agent.ExecutionCursor) (string, error)
}

func newKataCache(policy stickycache.Policy, values ...string) *kataCache {
	values = append(values, policy.PoolUUID, strconv.FormatUint(policy.VolumeBytes, 10))
	namespace := strings.Join(values, "\x00")
	legacy := sha256.Sum256([]byte(namespace))
	key := sha256.Sum256([]byte("trusted-org-workflow-v1\x00" + namespace))
	return &kataCache{lvm: stickycache.LVM{Policy: policy}, key: hex.EncodeToString(key[:]), legacyKey: hex.EncodeToString(legacy[:])}
}

func (c *kataCache) ownsKey(key string) bool {
	return key == c.key || key == c.legacyKey
}

func (c *Controller) cacheAuthorized(ctx context.Context, e agent.Execution) bool {
	var start protocol.StartCommand
	if json.Unmarshal(e.Command, &start) != nil ||
		start.Spec.TrustClass != "trusted" || start.Spec.Provider != "github" ||
		start.Spec.IsolationProfile != "isolated" {
		return false
	}
	remote, ok := c.Remote.(interface {
		KataCacheAccess(context.Context, agent.ExecutionCursor) (bool, error)
	})
	if !ok {
		return false
	}
	allowed, err := remote.KataCacheAccess(ctx, executionKey(e))
	return err == nil && allowed
}

// cachePlan is reapplied during recovery so inspect compares the exact Docker
// configuration recorded at launch, even across new published generations.
func (c *Controller) cachePlan(ctx context.Context, e agent.Execution, p dockerengine.Plan, prepare bool) (dockerengine.Plan, error) {
	if c.cache == nil {
		return p, nil
	}
	if p.Config == nil || p.HostConfig == nil || len(p.Name) != 68 || !strings.HasPrefix(p.Name, "nrd-") {
		return p, ErrReconcile
	}
	cursor := executionKey(e)
	v, exists, err := c.Store.KataCacheAttempt(ctx, cursor)
	if err != nil {
		return p, err
	}
	allowed := prepare && (!exists || v.State != "cold") && c.cacheAuthorized(ctx, e)
	if prepare && !exists {
		warmAllowed := false
		if allowed {
			var checkErr error
			warmAllowed, checkErr = c.cacheHeadroom(ctx)
			if checkErr != nil {
				return p, checkErr
			}
		}
		name := "nrdc-" + p.Name[4:52]
		if err = c.Store.BeginKataCache(ctx, c.Scope, cursor, c.cache.key, name, !warmAllowed); err != nil {
			return p, err
		}
		v, exists, err = c.Store.KataCacheAttempt(ctx, cursor)
		if err != nil || !exists {
			return p, errors.Join(ErrReconcile, err)
		}
	}
	if exists && !c.cache.ownsKey(v.Key) {
		return p, ErrReconcile
	}
	if exists && prepare && v.State != "cold" && (!allowed || v.Key != c.cache.key) {
		// Preserve existing device mappings for recovery. An issued container
		// with a cache prepared under obsolete authority cannot be started.
		return p, ErrReconcile
	}
	if exists && prepare && v.State == "preparing" {
		uuid, fs, err := c.cache.lvm.Prepare(ctx, v.Name, v.ParentUUID)
		if err != nil {
			if cleanupErr := c.cache.lvm.Delete(ctx, v.Name, ""); cleanupErr != nil {
				return p, errors.Join(err, cleanupErr)
			}
			if err = c.Store.ColdKataCache(ctx, v); err != nil {
				return p, err
			}
			v.State = "cold"
		} else {
			if err = c.Store.ReadyKataCache(ctx, v, uuid, fs); err != nil {
				return p, err
			}
			v.UUID, v.FilesystemUUID, v.State = uuid, fs, "ready"
		}
	}
	if len(p.Config.Cmd) != 2 || p.Config.Cmd[0] != "--block-storage" {
		return p, ErrReconcile
	}
	var settings katalinux.GuestBlockSettings
	if err = json.Unmarshal([]byte(p.Config.Cmd[1]), &settings); err != nil {
		return p, err
	}
	settings.Version = "runnerd09-guest-block-v3"
	var disk *cacheDisk
	if exists && v.FilesystemUUID != "" {
		policy := c.cache.lvm.Policy
		path := "/dev/" + policy.VolumeGroup + "/" + v.Name
		if prepare {
			path, err = c.cache.lvm.Device(ctx, v.Name, v.UUID)
			if err != nil {
				return p, err
			}
		}
		disk = &cacheDisk{Device: "/dev/neticora-buildkit", UUID: v.FilesystemUUID, Bytes: policy.VolumeBytes}
		p.HostConfig.Devices = append(p.HostConfig.Devices, container.DeviceMapping{PathOnHost: path, PathInContainer: disk.Device, CgroupPermissions: "rw"})
	}
	// Explicit null uses dedicated BuildKit on the ephemeral execution disk.
	payload, err := json.Marshal(struct {
		katalinux.GuestBlockSettings
		BuildKit *cacheDisk `json:"buildkit"`
	}{settings, disk})
	if err == nil {
		p.Config.Cmd = []string{"--block-storage", string(payload)}
	}
	return p, err
}

func (c *Controller) cacheHeadroom(ctx context.Context) (bool, error) {
	gcErr := c.cacheGarbage(ctx, c.cache.lvm.Policy.Retain)
	safe, probeErr := c.cache.lvm.Headroom(ctx, c.HostLimits.Slots)
	if gcErr == nil && probeErr == nil && !safe && c.cache.lvm.Policy.Retain > 1 {
		gcErr = c.cacheGarbage(ctx, 1)
		safe, probeErr = c.cache.lvm.Headroom(ctx, c.HostLimits.Slots)
	}
	if gcErr != nil || probeErr != nil || !safe {
		return false, nil
	}
	head, warm, err := c.Store.KataCacheHead(ctx, c.cache.key)
	if err != nil {
		return false, err
	}
	return !warm || c.cache.lvm.Retained(ctx, head.Name, head.UUID), nil
}

type cacheDisk struct {
	Device string `json:"device"`
	UUID   string `json:"uuid"`
	Bytes  uint64 `json:"bytes"`
}

func (c *Controller) cacheCleanExit(ctx context.Context, e agent.Execution, o dockerengine.Object) error {
	if c.cache == nil || o.ID == "" || o.State != "exited" || o.ExitCode != 0 || o.OOMKilled {
		return nil
	}
	v, ok, err := c.Store.KataCacheAttempt(ctx, executionKey(e))
	if err != nil || !ok || v.Key != c.cache.key || v.State != "ready" || v.CleanExitAt > 0 {
		return err
	}
	return c.Store.MarkKataCacheCleanExit(ctx, v)
}

func (c *Controller) finishCache(ctx context.Context, e agent.Execution, allowSuccess bool) error {
	if c.cache == nil {
		return nil
	}
	v, exists, err := c.Store.KataCacheAttempt(ctx, executionKey(e))
	if err != nil || !exists {
		return err
	}
	if !c.cache.ownsKey(v.Key) {
		return ErrReconcile
	}
	if v.State == "cold" || v.State == "retained" {
		return nil
	}
	if v.State == "discard" {
		return c.deleteCache(ctx, v)
	}
	detached, err := c.cache.lvm.Detach(ctx, v.Name, v.UUID)
	if err != nil {
		return err
	}
	if v.State == "ready" && !detached {
		return stickycache.ErrVolume
	}
	promote := false
	if allowSuccess && v.Key == c.cache.key && detached && v.CleanExitAt > 0 {
		if remote, ok := c.Remote.(cacheOutcomeRemote); ok {
			decision, err := remote.KataCacheDecision(ctx, executionKey(e))
			if (err != nil || decision == "pending") && time.Since(time.Unix(v.CleanExitAt, 0)) < time.Minute {
				return errors.Join(ErrReconcile, err)
			}
			promote = err == nil && decision == "success"
		}
	}
	if err = c.Store.CompleteKataCache(ctx, v, promote); err != nil {
		return err
	}
	v, exists, err = c.Store.KataCacheAttempt(ctx, executionKey(e))
	if err != nil || !exists {
		return errors.Join(ErrReconcile, err)
	}
	if v.State == "discard" {
		return c.deleteCache(ctx, v)
	}
	return nil
}

func (c *Controller) deleteCache(ctx context.Context, v journal.KataCacheVolume) error {
	if err := c.cache.lvm.Delete(ctx, v.Name, v.UUID); err != nil {
		return err
	}
	return c.Store.ForgetKataCache(ctx, v)
}

func (c *Controller) cacheGarbage(ctx context.Context, retained int) error {
	items, err := c.Store.KataCacheGarbage(ctx, c.cache.key, retained)
	if err != nil {
		return err
	}
	for _, v := range items {
		if err = c.deleteCache(ctx, v); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) reportCachePresence(ctx context.Context) {
	remote, ok := c.Remote.(interface {
		ReportKataCache(context.Context, string, string, bool) error
	})
	if !ok {
		return
	}
	head, exists, err := c.Store.KataCacheHead(ctx, c.cache.key)
	warm := false
	if err == nil && exists {
		available, poolErr := c.cache.lvm.Headroom(ctx, c.HostLimits.Slots)
		warm = available && poolErr == nil && c.cache.lvm.Retained(ctx, head.Name, head.UUID)
	}
	_ = remote.ReportKataCache(ctx, c.Repository, c.Kata.ID, warm)
}
