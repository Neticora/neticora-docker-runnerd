package execution

import (
	"context"
	"log/slog"
	"os"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/internal/stickycache"
)

var stickyCacheLog = slog.New(slog.NewJSONHandler(os.Stderr, nil))

func (c *Controller) cacheDiagnostic(e agent.Execution, stage, result string, attrs ...slog.Attr) {
	if c.cache == nil {
		return
	}
	fields := []slog.Attr{
		slog.String("stage", stage), slog.String("result", result),
		slog.String("execution_id", e.Identity.ExecutionID), slog.String("execution_generation", e.Identity.Generation),
		slog.String("session_epoch", c.Scope.SessionEpoch), slog.String("cache_namespace", c.cache.key),
		slog.String("thin_pool_uuid", stickycache.DiagnosticUUID(c.cache.lvm.Policy.PoolUUID)),
	}
	stickyCacheLog.LogAttrs(context.Background(), slog.LevelInfo, "sticky_cache", append(fields, attrs...)...)
}

func (c *Controller) observeCacheLVM(e agent.Execution, event stickycache.Diagnostic) {
	var attrs []slog.Attr
	if event.Command != "" {
		attrs = append(attrs, slog.String("command", event.Command), slog.Int("exit_status", event.ExitStatus))
	}
	if event.PoolBytes != 0 {
		attrs = append(attrs, slog.Uint64("pool_bytes", event.PoolBytes),
			slog.Float64("data_percent", event.DataPercent), slog.Float64("metadata_percent", event.MetadataPercent),
			slog.Uint64("reservation_slots", event.ReservationSlots), slog.Uint64("volume_bytes", event.VolumeBytes),
			slog.Float64("reservation_percent", event.ReservationPercent),
			slog.Int("max_data_percent", int(event.MaxDataPercent)), slog.Int("max_metadata_percent", int(event.MaxMetadataPercent)))
	}
	if event.LVUUID != "" {
		attrs = append(attrs, slog.String("lv_uuid", event.LVUUID))
	}
	if event.FilesystemUUID != "" {
		attrs = append(attrs, slog.String("filesystem_uuid", event.FilesystemUUID))
	}
	c.cacheDiagnostic(e, event.Stage, event.Result, attrs...)
}
