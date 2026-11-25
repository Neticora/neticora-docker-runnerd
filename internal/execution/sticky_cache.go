package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/stickycache"
	"github.com/Neticora/neticora-docker-runnerd/journal"
	"github.com/Neticora/neticora-docker-runnerd/transport"
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
	return c.cacheAccess(ctx, e) == "allowed"
}

func (c *Controller) cacheAccess(ctx context.Context, e agent.Execution) string {
	var start protocol.StartCommand
	if json.Unmarshal(e.Command, &start) != nil ||
		start.Spec.TrustClass != "trusted" || start.Spec.Provider != "github" ||
		start.Spec.IsolationProfile != "isolated" {
		c.cacheDiagnostic(e, "cache-authorization", "local-policy-ineligible")
		return "local-policy-ineligible"
	}
	remote, ok := c.Remote.(interface {
		KataCacheAccess(context.Context, agent.ExecutionCursor) (bool, error)
	})
	if !ok {
		c.cacheDiagnostic(e, "cache-authorization", "platform-access-unavailable")
		return "platform-access-unavailable"
	}
	started := time.Now()
	allowed, err := remote.KataCacheAccess(ctx, executionKey(e))
	result := "platform-denied"
	attrs := []slog.Attr{slog.Int64("elapsed_ms", time.Since(started).Milliseconds())}
	if err != nil {
		result = "platform-request-failed"
		kind, status := transport.RequestFailureDetails(err)
		attrs = append(attrs, slog.String("error_kind", kind), slog.Int("http_status", status))
	} else if allowed {
		result = "allowed"
	}
	c.cacheDiagnostic(e, "cache-authorization", result, attrs...)
	return result
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
	access := ""
	if prepare && (!exists || v.State != "cold") {
		access = c.cacheAccess(ctx, e)
	}
	if prepare && !exists {
		fallback := access
		if access == "allowed" {
			var checkErr error
			fallback, checkErr = c.cacheHeadroom(ctx, e)
			if checkErr != nil {
				return p, checkErr
			}
		}
		name := cacheVolumeName(p)
		if err = c.Store.BeginKataCache(ctx, c.Scope, cursor, c.cache.key, name, fallback != ""); err != nil {
			return p, err
		}
		v, exists, err = c.Store.KataCacheAttempt(ctx, cursor)
		if err != nil || !exists {
			return p, errors.Join(ErrReconcile, err)
		}
		if fallback != "" {
			c.cacheDiagnostic(e, "cold-fallback", fallback)
		}
	}
	if exists && !c.cache.ownsKey(v.Key) {
		return p, ErrReconcile
	}
	if exists && prepare && v.State != "cold" && (access != "allowed" || v.Key != c.cache.key) {
		// Preserve existing device mappings for recovery. An issued container
		// with a cache prepared under obsolete authority cannot be started.
		return p, ErrReconcile
	}
	if exists && prepare && v.State == "preparing" {
		failedStage := ""
		lvm := c.cache.lvm.WithDiagnostics(func(event stickycache.Diagnostic) {
			c.observeCacheLVM(e, event)
			if event.Stage != "lvm-command" && event.Result == "failed" {
				failedStage = event.Stage
			}
		})
		c.cacheDiagnostic(e, "snapshot-prepare", "started", slog.String("parent_lv_uuid", stickycache.DiagnosticUUID(v.ParentUUID)))
		uuid, fs, err := lvm.Prepare(ctx, v.Name, v.ParentUUID)
		if err != nil {
			if cleanupErr := lvm.Delete(ctx, v.Name, ""); cleanupErr != nil {
				c.cacheDiagnostic(e, "snapshot-rollback", "failed")
				return p, errors.Join(err, cleanupErr)
			}
			if err = c.Store.ColdKataCache(ctx, v); err != nil {
				return p, err
			}
			v.State = "cold"
			c.cacheDiagnostic(e, "cold-fallback", failedStage)
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
			lvm := c.cache.lvm.WithDiagnostics(func(event stickycache.Diagnostic) { c.observeCacheLVM(e, event) })
			path, err = lvm.Device(ctx, v.Name, v.UUID)
			if err != nil {
				c.cacheDiagnostic(e, "cache-device", "verification-failed", slog.String("lv_uuid", stickycache.DiagnosticUUID(v.UUID)))
				return p, err
			}
			c.cacheDiagnostic(e, "cache-device", "verified", slog.String("lv_uuid", stickycache.DiagnosticUUID(v.UUID)),
				slog.String("parent_lv_uuid", stickycache.DiagnosticUUID(v.ParentUUID)))
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

// cacheHeadroom returns an empty fallback reason when allocation can proceed.
func (c *Controller) cacheHeadroom(ctx context.Context, e agent.Execution) (string, error) {
	reason := "pool-inventory-unavailable"
	lvm := c.cache.lvm.WithDiagnostics(func(event stickycache.Diagnostic) {
		c.observeCacheLVM(e, event)
		if event.Stage == "headroom" {
			reason = event.Result
		}
	})
	var gcErr error
	gc := func(retained int) {
		var removed int
		removed, gcErr = c.collectCacheGarbage(ctx, lvm, retained)
		outcome := "complete"
		if gcErr != nil {
			outcome = "failed"
		}
		c.cacheDiagnostic(e, "garbage-collection", outcome, slog.Int("retain", retained), slog.Int("removed", removed))
	}
	gc(lvm.Policy.Retain)
	safe, probeErr := lvm.Headroom(ctx, c.HostLimits.Slots)
	if gcErr == nil && probeErr == nil && !safe && lvm.Policy.Retain > 1 {
		gc(1)
		reason = "pool-inventory-unavailable"
		safe, probeErr = lvm.Headroom(ctx, c.HostLimits.Slots)
	}
	if gcErr != nil {
		return "garbage-collection-failed", nil
	}
	if probeErr != nil || !safe {
		return reason, nil
	}
	head, warm, err := c.Store.KataCacheHead(ctx, c.cache.key)
	if err != nil {
		c.cacheDiagnostic(e, "committed-generation", "journal-unavailable")
		return "", err
	}
	if !warm {
		c.cacheDiagnostic(e, "committed-generation", "empty")
		return "", nil
	}
	c.cacheDiagnostic(e, "committed-generation", "found",
		slog.String("committed_execution_id", head.ExecutionID), slog.String("committed_execution_generation", head.Generation),
		slog.String("lv_uuid", stickycache.DiagnosticUUID(head.UUID)))
	if !lvm.Retained(ctx, head.Name, head.UUID) {
		return "retained-volume-not-verified", nil
	}
	return "", nil
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
	_, err := c.collectCacheGarbage(ctx, c.cache.lvm, retained)
	return err
}

func (c *Controller) collectCacheGarbage(ctx context.Context, lvm stickycache.LVM, retained int) (int, error) {
	items, err := c.Store.KataCacheGarbage(ctx, c.cache.key, retained)
	if err != nil {
		return 0, err
	}
	for i, v := range items {
		if err = lvm.Delete(ctx, v.Name, v.UUID); err != nil {
			return i, err
		}
		if err = c.Store.ForgetKataCache(ctx, v); err != nil {
			return i, err
		}
	}
	return len(items), nil
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

// cacheVolumeName is defined by the deterministic execution plan name.
func cacheVolumeName(p dockerengine.Plan) string { return "nrdc-" + p.Name[4:52] }
