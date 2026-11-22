//go:build !linux

package telemetry

import (
	"strconv"
	"time"
)

type cpuState struct{ at time.Time }

func U(v uint64) *string { s := strconv.FormatUint(v, 10); return &s }
func (s *Sampler) sampleCPU() CPU {
	return CPU{Observation: Stamp("host", "proc-stat-delta", "unsupported")}
}
func sampleMemory() Memory { return Memory{Observation: Stamp("host", "proc-meminfo", "unsupported")} }
func sampleFilesystem(path string) Filesystem {
	return Filesystem{Observation: Stamp("filesystem", "statfs", "unsupported"), Path: path}
}
