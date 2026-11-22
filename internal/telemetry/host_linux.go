//go:build linux

package telemetry

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type cpuState struct {
	total, idle uint64
	at          time.Time
}

func U(v uint64) *string { s := strconv.FormatUint(v, 10); return &s }
func parseCPU(raw string) (uint64, uint64, int, bool) {
	var total, idle uint64
	cores := 0
	found := false
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] == "cpu" {
			if len(f) < 5 {
				return 0, 0, 0, false
			}
			for i := 1; i < len(f) && i <= 8; i++ {
				n, err := strconv.ParseUint(f[i], 10, 64)
				if err != nil || ^uint64(0)-total < n {
					return 0, 0, 0, false
				}
				total += n
				if i == 4 || i == 5 {
					idle += n
				}
			}
			found = true
		} else if strings.HasPrefix(f[0], "cpu") {
			if _, err := strconv.Atoi(strings.TrimPrefix(f[0], "cpu")); err == nil {
				cores++
			}
		}
	}
	return total, idle, cores, found && cores > 0 && idle <= total
}
func (s *Sampler) sampleCPU() CPU {
	o := CPU{Observation: Stamp("host", "proc-stat-delta", "unavailable")}
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return o
	}
	total, idle, cores, ok := parseCPU(string(raw))
	if !ok {
		return o
	}
	o.LogicalCores = &cores
	now := time.Now()
	previous := s.cpu
	s.cpu = cpuState{total, idle, now}
	o.Status = "warming-up"
	if previous.at.IsZero() || total <= previous.total || idle < previous.idle {
		return o
	}
	delta := total - previous.total
	idleDelta := idle - previous.idle
	if idleDelta > delta {
		return o
	}
	millis := now.Sub(previous.at).Milliseconds()
	if millis <= 0 {
		return o
	}
	percent := int(float64(delta-idleDelta) / float64(delta) * 10000)
	if percent < 0 || percent > 10000 {
		return o
	}
	o.Status = "available"
	o.UtilizationBasisPoints = &percent
	o.SampleMilliseconds = U(uint64(millis))
	return o
}
func parseMemory(raw string) (uint64, uint64, bool) {
	values := map[string]uint64{}
	scan := bufio.NewScanner(strings.NewReader(raw))
	for scan.Scan() {
		f := strings.Fields(scan.Text())
		if len(f) != 3 || f[2] != "kB" {
			continue
		}
		if f[0] != "MemTotal:" && f[0] != "MemAvailable:" {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil || n > ^uint64(0)/1024 {
			return 0, 0, false
		}
		values[f[0]] = n * 1024
	}
	total, t := values["MemTotal:"]
	available, a := values["MemAvailable:"]
	return total, available, t && a && total > 0 && available <= total && scan.Err() == nil
}
func sampleMemory() Memory {
	o := Memory{Observation: Stamp("host", "proc-meminfo", "unavailable")}
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return o
	}
	total, available, ok := parseMemory(string(raw))
	if !ok {
		return o
	}
	o.Status = "available"
	o.TotalBytes = U(total)
	o.AvailableBytes = U(available)
	o.UsedBytes = U(total - available)
	return o
}
func sampleFilesystem(path string) Filesystem {
	o := Filesystem{Observation: Stamp("filesystem", "statfs", "unavailable"), Path: path}
	var fs syscall.Statfs_t
	if syscall.Statfs(path, &fs) != nil || fs.Bsize <= 0 || fs.Blocks > ^uint64(0)/uint64(fs.Bsize) || fs.Bfree > fs.Blocks || fs.Bavail > fs.Bfree {
		return o
	}
	size := uint64(fs.Bsize)
	o.Status = "available"
	o.TotalBytes = U(fs.Blocks * size)
	o.FreeBytes = U(fs.Bfree * size)
	o.AvailableBytes = U(fs.Bavail * size)
	o.UsedBytes = U((fs.Blocks - fs.Bfree) * size)
	id := fmt.Sprintf("%x:%x", uint32(fs.Fsid.X__val[0]), uint32(fs.Fsid.X__val[1]))
	o.FilesystemID = &id
	if fs.Files > 0 && fs.Ffree <= fs.Files {
		o.TotalInodes = U(fs.Files)
		o.FreeInodes = U(fs.Ffree)
	}
	return o
}
