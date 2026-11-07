package katalinux

import (
	"encoding/hex"
	"math"
	"path/filepath"
	"strconv"
	"strings"
)

// HostCgroup is an independent hard host boundary. Guest cgroup administration
// never authorizes changing the ancestor slice or its CPU/memory/PID ceilings.
type HostCgroup struct {
	Method          string `json:"method"`
	SystemctlBinary string `json:"systemctlBinary"`
	BusctlBinary    string `json:"busctlBinary"`
	PidsLimit       uint64 `json:"pidsLimit"`
}

type CgroupRecord struct {
	Version     string `json:"version"`
	Profile     string `json:"profile"`
	Name        string `json:"name"`
	Unit        string `json:"unit"`
	Path        string `json:"path"`
	Owner       string `json:"owner"`
	BootID      string `json:"bootId"`
	Device      uint64 `json:"device"`
	Inode       uint64 `json:"inode"`
	CPUQuota    uint64 `json:"cpuQuotaPerSecUSec"`
	MemoryBytes uint64 `json:"memoryBytes"`
	PidsLimit   uint64 `json:"pidsLimit"`
	Phase       string `json:"phase"`
}

func hostCgroupUnit(name string) string {
	if !strings.HasPrefix(name, "nrd-") || len(name) != 68 {
		return ""
	}
	if _, err := hex.DecodeString(name[4:]); err != nil || strings.ToLower(name) != name {
		return ""
	}
	return "neticora-runnerd-e" + name[4:] + ".slice"
}

func sameHostCgroup(a, b *CgroupRecord) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	x, y := *a, *b
	x.Phase, y.Phase = "", ""
	return x == y
}

func hostCgroupPath(name string) string {
	unit := hostCgroupUnit(name)
	if unit == "" {
		return ""
	}
	return "/neticora.slice/neticora-runnerd.slice/" + unit
}

func validateHostCgroup(m Manifest) error {
	c := m.HostCgroup
	if c == nil || c.Method != "systemd-transient-slice-v1" || c.PidsLimit < 64 || c.PidsLimit > 4096 {
		return ErrQualification
	}
	for _, binary := range []string{c.SystemctlBinary, c.BusctlBinary} {
		if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary || binary == "/" || strings.ContainsRune(binary, 0) || len(m.Files[binary]) != 64 {
			return ErrQualification
		}
	}
	if c.SystemctlBinary == c.BusctlBinary {
		return ErrQualification
	}
	cpu, err := strconv.ParseUint(m.Budget.Effective.CpuMillis, 10, 64)
	memory, err2 := strconv.ParseUint(m.Budget.Effective.MemoryBytes, 10, 64)
	if err != nil || err2 != nil || cpu == 0 || cpu > 128000 || memory == 0 || memory > 9007199254740991 || memory > math.MaxInt64 || memory%4096 != 0 {
		return ErrQualification
	}
	return nil
}
