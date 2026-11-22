// Package telemetry collects observations, never execution capacity or policy.
package telemetry

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const Version = "runnerd08-resource-observations-v1"

type Observation struct {
	Scope      string `json:"scope"`
	Source     string `json:"source"`
	ObservedAt string `json:"observedAt"`
	Status     string `json:"status"`
}

func Stamp(scope, source, status string) Observation {
	return Observation{scope, source, time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), status}
}

type CPU struct {
	Observation
	LogicalCores           *int    `json:"logicalCores"`
	UtilizationBasisPoints *int    `json:"utilizationBasisPoints"`
	SampleMilliseconds     *string `json:"sampleMilliseconds"`
}
type Memory struct {
	Observation
	TotalBytes     *string `json:"totalBytes"`
	AvailableBytes *string `json:"availableBytes"`
	UsedBytes      *string `json:"usedBytes"`
}
type Filesystem struct {
	Observation
	Path           string  `json:"path"`
	FilesystemID   *string `json:"filesystemId"`
	TotalBytes     *string `json:"totalBytes"`
	FreeBytes      *string `json:"freeBytes"`
	AvailableBytes *string `json:"availableBytes"`
	UsedBytes      *string `json:"usedBytes"`
	TotalInodes    *string `json:"totalInodes"`
	FreeInodes     *string `json:"freeInodes"`
}
type Docker struct {
	Observation
	ImagesBytes         *string `json:"imagesBytes"`
	WritableLayersBytes *string `json:"writableLayersBytes"`
	VolumesBytes        *string `json:"volumesBytes"`
	BuildCacheBytes     *string `json:"buildCacheBytes"`
	Containers          *string `json:"containers"`
	ActiveContainers    *string `json:"activeContainers"`
}
type Target struct{ ExecutionID, Generation, ResourceID string }
type Execution struct {
	Observation
	ExecutionID         string  `json:"executionId"`
	Generation          string  `json:"generation"`
	ResourceID          string  `json:"resourceId"`
	CPUUsageNanoseconds *string `json:"cpuUsageNanoseconds"`
	MemoryUsageBytes    *string `json:"memoryUsageBytes"`
	MemoryLimitBytes    *string `json:"memoryLimitBytes"`
	WritableLayerBytes  *string `json:"writableLayerBytes"`
	Pids                *string `json:"pids"`
}

func MissingExecution(t Target) Execution {
	return Execution{Observation: Stamp("execution", "docker-container-stats", "unavailable"), ExecutionID: t.ExecutionID, Generation: t.Generation, ResourceID: t.ResourceID}
}

type RuntimeMetrics struct {
	Docker     Docker
	Root       string
	Executions []Execution
	Complete   bool
}
type Runtime interface {
	ObserveResources(context.Context, []Target) (RuntimeMetrics, error)
}
type Sample struct {
	Version            string       `json:"version"`
	EndpointIdentity   string       `json:"endpointIdentity"`
	ObservedAt         string       `json:"observedAt"`
	CPU                CPU          `json:"cpu"`
	Memory             Memory       `json:"memory"`
	Filesystems        []Filesystem `json:"filesystems"`
	Docker             Docker       `json:"docker"`
	ExecutionsComplete bool         `json:"executionsComplete"`
	Executions         []Execution  `json:"executions"`
}
type Sampler struct {
	fsBusy  atomic.Bool
	fsProbe func(string) Filesystem
	mu      sync.Mutex
	Paths   []string
	cpu     cpuState
}

func (s *Sampler) Collect(ctx context.Context, endpoint string, r Runtime, targets []Target, complete bool) Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Sample{Version: Version, EndpointIdentity: endpoint, CPU: s.sampleCPU(), Memory: sampleMemory(), Filesystems: []Filesystem{}, Docker: Docker{Observation: Stamp("docker-daemon", "docker-system-df", "unavailable")}, Executions: []Execution{}}
	paths := append([]string{"/"}, s.Paths...)
	if r != nil {
		budget, cancel := context.WithTimeout(ctx, 4*time.Second)
		metrics, err := r.ObserveResources(budget, targets)
		cancel()
		if err == nil {
			out.Docker = metrics.Docker
			out.Executions = metrics.Executions
			out.ExecutionsComplete = complete && metrics.Complete
			if metrics.Root != "" {
				paths = append(paths, metrics.Root)
			}
		}
	}
	if out.Executions == nil {
		out.Executions = []Execution{}
	}
	if len(out.Executions) == 0 && len(targets) > 0 {
		for _, t := range targets {
			out.Executions = append(out.Executions, MissingExecution(t))
		}
	}
	sort.Strings(paths)
	previous := ""
	for _, path := range paths {
		if path == previous || !strings.HasPrefix(path, "/") || !utf8.ValidString(path) || len(path) > 1024 {
			continue
		}
		previous = path
		if len(out.Filesystems) == 32 {
			break
		}
		out.Filesystems = append(out.Filesystems, s.filesystem(ctx, path))
	}
	out.ObservedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	return out
}

// One bounded outstanding filesystem probe prevents a slow customer mount from
// blocking heartbeats or creating an unbounded goroutine queue.
func (s *Sampler) filesystem(ctx context.Context, path string) Filesystem {
	missing := Filesystem{Observation: Stamp("filesystem", "statfs", "unavailable"), Path: path}
	if !s.fsBusy.CompareAndSwap(false, true) {
		return missing
	}
	probe := s.fsProbe
	if probe == nil {
		probe = sampleFilesystem
	}
	done := make(chan Filesystem, 1)
	go func() { defer s.fsBusy.Store(false); done <- probe(path) }()
	budget, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	select {
	case value := <-done:
		return value
	case <-budget.Done():
		return missing
	}
}
