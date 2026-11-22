//go:build linux

package telemetry

import (
	"context"
	"encoding/json"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"testing"
	"time"
)

func TestMetricsHaveScopeFreshnessAndUnknownsAreNotZero(t *testing.T) {
	s := &Sampler{Paths: []string{"/", "/path/not-present"}}
	first := s.Collect(context.Background(), "engine", nil, nil, false)
	if first.CPU.Status != "warming-up" || first.CPU.UtilizationBasisPoints != nil || first.Docker.ImagesBytes != nil || first.Docker.Status != "unavailable" {
		t.Fatal("unknown metrics fabricated", first)
	}
	time.Sleep(20 * time.Millisecond)
	next := s.Collect(context.Background(), "engine", nil, nil, false)
	if next.CPU.Status != "available" || next.CPU.UtilizationBasisPoints == nil || next.Memory.TotalBytes == nil {
		t.Fatal("host observations missing", next)
	}
	for _, fs := range next.Filesystems {
		if fs.Path == "/path/not-present" && (fs.Status != "unavailable" || fs.TotalBytes != nil) {
			t.Fatal("unknown filesystem fabricated")
		}
	}
	raw, _ := json.Marshal(next)
	if err := protocol.ValidateInboundJSON("ResourceTelemetry", raw); err != nil {
		t.Fatal(string(raw), err)
	}
}
func TestCpuCountersExcludeGuestDoubleCountAndReset(t *testing.T) {
	total, idle, cores, ok := parseCPU("cpu 100 20 30 400 50 2 3 4 99 88\ncpu0 1\ncpu1 1\n")
	if !ok || total != 609 || idle != 450 || cores != 2 {
		t.Fatal(total, idle, cores, ok)
	}
	if _, _, ok := parseMemory("MemTotal: 100 kB\nMemAvailable: 101 kB\n"); ok {
		t.Fatal("inconsistent memory accepted")
	}
}

func TestSlowFilesystemCannotBlockHeartbeatsOrQueueUnboundedProbes(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	s := &Sampler{Paths: []string{"/slow"}, fsProbe: func(path string) Filesystem { <-block; return sampleFilesystem(path) }}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	sample := s.Collect(ctx, "engine", nil, nil, false)
	if time.Since(start) > time.Second {
		t.Fatal("filesystem blocked observations")
	}
	if len(sample.Filesystems) != 2 || sample.Filesystems[0].Status != "unavailable" || sample.Filesystems[0].TotalBytes != nil {
		t.Fatal("timeout fabricated filesystem values")
	}
}
