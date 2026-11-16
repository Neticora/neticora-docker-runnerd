package dockerengine

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/Neticora/neticora-docker-runnerd/internal/telemetry"
	"github.com/moby/moby/client"
	"github.com/moby/moby/client/pkg/versions"
)

func measured(v int64) *string {
	if v < 0 {
		return nil
	}
	return telemetry.U(uint64(v))
}
func counter(v *uint64) *string {
	if v == nil {
		return nil
	}
	return telemetry.U(*v)
}

// ObserveResources contains only bounded read operations. Targets must come from
// controller-verified original plans; connection-only mode supplies no targets.
func (e *Engine) ObserveResources(ctx context.Context, targets []telemetry.Target) (telemetry.RuntimeMetrics, error) {
	out := telemetry.RuntimeMetrics{Docker: telemetry.Docker{Observation: telemetry.Stamp("docker-daemon", "docker-system-df", "unavailable")}, Executions: []telemetry.Execution{}, Complete: true}
	if err := e.check(ctx); err != nil {
		return out, err
	}
	info, err := e.api.Info(ctx, client.InfoOptions{})
	if err != nil {
		return out, err
	}
	if filepath.IsAbs(info.Info.DockerRootDir) && filepath.Clean(info.Info.DockerRootDir) == info.Info.DockerRootDir {
		out.Root = info.Info.DockerRootDir
	}
	// Older API versions return unbounded detailed lists; do not request them just
	// to fabricate an aggregate. Unsupported observations never block execution.
	if versions.LessThan(e.api.ClientVersion(), "1.56") {
		out.Docker.Status = "unsupported"
	} else {
		disk, err := e.api.DiskUsage(ctx, client.DiskUsageOptions{Images: true, Containers: true, Volumes: true, BuildCache: true})
		if err == nil {
			out.Docker = telemetry.Docker{Observation: telemetry.Stamp("docker-daemon", "docker-system-df", "available"), ImagesBytes: measured(disk.Images.TotalSize), WritableLayersBytes: measured(disk.Containers.TotalSize), VolumesBytes: measured(disk.Volumes.TotalSize), BuildCacheBytes: measured(disk.BuildCache.TotalSize), Containers: measured(disk.Containers.TotalCount), ActiveContainers: measured(disk.Containers.ActiveCount)}
		}
	}
	if len(targets) > 32 {
		out.Complete = false
		targets = targets[:32]
	}
	for _, target := range targets {
		value := telemetry.MissingExecution(target)
		sample, err := e.api.ContainerStats(ctx, target.ResourceID, client.ContainerStatsOptions{})
		if err == nil {
			var stats struct {
				Read string `json:"read"`
				CPU  struct {
					Usage struct {
						Total *uint64 `json:"total_usage"`
					} `json:"cpu_usage"`
				} `json:"cpu_stats"`
				Memory struct {
					Usage *uint64 `json:"usage"`
					Limit *uint64 `json:"limit"`
				} `json:"memory_stats"`
				Pids struct {
					Current *uint64 `json:"current"`
				} `json:"pids_stats"`
			}
			err = json.NewDecoder(io.LimitReader(sample.Body, 1<<20)).Decode(&stats)
			sample.Body.Close()
			if err == nil && stats.Read != "" && stats.Read != "0001-01-01T00:00:00Z" {
				value.Observation = telemetry.Stamp("execution", "docker-container-stats", "available")
				value.CPUUsageNanoseconds = counter(stats.CPU.Usage.Total)
				value.MemoryUsageBytes = counter(stats.Memory.Usage)
				value.MemoryLimitBytes = counter(stats.Memory.Limit)
				value.Pids = counter(stats.Pids.Current)
			}
		}
		// No expensive writable-tree scan. SizeRw remains unknown unless the daemon
		// supplies it; it must not be replaced with a requested storage budget.
		if value.Status != "available" {
			out.Complete = false
		}
		out.Executions = append(out.Executions, value)
	}
	if err := e.check(ctx); err != nil {
		return telemetry.RuntimeMetrics{}, err
	}
	return out, nil
}
