//go:build linux

package katalinux

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

func cgroupReadyTestStatus(record CgroupRecord) map[string]string {
	return map[string]string{"LoadState": "loaded", "ActiveState": "active", "Transient": "yes", "Description": cgroupDescription(record), "ControlGroup": record.Path, "FragmentPath": "/run/systemd/transient/" + hostCgroupUnit(record.Name), "SourcePath": "", "DropInPaths": ""}
}

func TestHostCgroupWaitsForQueuedUnitAndKernelDirectory(t *testing.T) {
	record := CgroupRecord{Name: "nrd-" + strings.Repeat("a", 64), Owner: strings.Repeat("b", 64)}
	record.Path = hostCgroupPath(record.Name)
	reads, inspections := 0, 0
	stat, err := waitHostCgroupReady(t.Context(), record, func(context.Context) (map[string]string, error) {
		reads++
		s := cgroupReadyTestStatus(record)
		if reads == 1 {
			s["LoadState"], s["ActiveState"], s["Transient"], s["ControlGroup"] = "not-found", "inactive", "no", ""
			s["FragmentPath"] = ""
		} else if reads == 2 {
			s["ActiveState"], s["ControlGroup"] = "activating", ""
		}
		return s, nil
	}, func(CgroupRecord) (syscall.Stat_t, bool, error) {
		inspections++
		if inspections == 1 {
			return syscall.Stat_t{}, false, os.ErrNotExist
		}
		return syscall.Stat_t{Dev: 12, Ino: 34}, false, nil
	})
	if err != nil || stat.Dev != 12 || stat.Ino != 34 || reads != 4 || inspections != 2 {
		t.Fatalf("queued creation not observed safely: reads=%d inspections=%d error=%v", reads, inspections, err)
	}
}

func TestHostCgroupReadinessFencesConflictsAndInvalidLimits(t *testing.T) {
	record := CgroupRecord{Name: "nrd-" + strings.Repeat("a", 64), Path: "/owned"}
	for _, field := range []string{"Description", "ControlGroup", "Transient", "FragmentPath", "SourcePath", "DropInPaths", "ActiveState", "limits", "populated"} {
		t.Run(field, func(t *testing.T) {
			reads := 0
			_, err := waitHostCgroupReady(t.Context(), record, func(context.Context) (map[string]string, error) {
				reads++
				s := cgroupReadyTestStatus(record)
				if field != "limits" && field != "populated" {
					s[field] = "foreign-or-failed"
				}
				return s, nil
			}, func(CgroupRecord) (syscall.Stat_t, bool, error) {
				if field == "limits" {
					return syscall.Stat_t{}, false, ErrQualification
				}
				return syscall.Stat_t{}, field == "populated", nil
			})
			if err == nil || reads != 1 {
				t.Fatal("conflicting or unsafe state retried/adopted", err, reads)
			}
		})
	}
}

func TestHostCgroupReadinessHonorsDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	_, err := waitHostCgroupReady(ctx, CgroupRecord{}, func(context.Context) (map[string]string, error) {
		return map[string]string{"LoadState": "not-found", "ActiveState": "inactive"}, nil
	}, func(CgroupRecord) (syscall.Stat_t, bool, error) {
		t.Fatal("kernel inspected before owned active unit")
		return syscall.Stat_t{}, false, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrQualification) {
		t.Fatal("readiness deadline not retained", err)
	}
}

func TestHostCgroupScopeCannotSelectArbitraryUnitsOrPaths(t *testing.T) {
	for _, name := range []string{"", "system.slice", "nrd-" + strings.Repeat("A", 64), "nrd-" + strings.Repeat("/", 64), "nrd-" + strings.Repeat("x", 64)} {
		if hostCgroupUnit(name) != "" || hostCgroupPath(name) != "" {
			t.Fatal("unowned cgroup scope accepted", name)
		}
	}
	a, b := "nrd-"+strings.Repeat("a", 64), "nrd-"+strings.Repeat("b", 64)
	if hostCgroupUnit(a) == hostCgroupUnit(b) || !strings.HasPrefix(hostCgroupPath(a), "/neticora.slice/neticora-runnerd.slice/") {
		t.Fatal("per-attempt host boundary is not distinct and confined")
	}
}

func TestHostCgroupRejectsUnpinnedOrUnboundedPolicy(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"missing":          func(m *Manifest) { m.HostCgroup = nil },
		"method":           func(m *Manifest) { m.HostCgroup.Method = "soft" },
		"unbounded PID":    func(m *Manifest) { m.HostCgroup.PidsLimit = 0 },
		"excess PID":       func(m *Manifest) { m.HostCgroup.PidsLimit = 4097 },
		"binary alias":     func(m *Manifest) { m.HostCgroup.BusctlBinary = m.HostCgroup.SystemctlBinary },
		"missing pin":      func(m *Manifest) { delete(m.Files, m.HostCgroup.BusctlBinary) },
		"unsafe path":      func(m *Manifest) { m.HostCgroup.BusctlBinary = "/qualified/../busctl" },
		"oversized CPU":    func(m *Manifest) { m.Budget.Effective.CpuMillis = "128001" },
		"unaligned memory": func(m *Manifest) { m.Budget.Effective.MemoryBytes = "1342177281" },
	} {
		t.Run(name, func(t *testing.T) {
			m := multiBlockFixture()
			mutate(&m)
			if validateHostCgroup(m) == nil {
				t.Fatal("invalid host boundary policy accepted")
			}
		})
	}
}

func TestV3PlanSeparatesGuestLimitsFromHostReservation(t *testing.T) {
	p := profile(multiBlockFixture())
	s := protocol.ExecutionSpec{ExecutionId: "execution", AttemptId: "attempt", Generation: "1", SpecHash: strings.Repeat("a", 64), IsolationProfile: "isolated", ProfileVersion: p.ID, TemplateVersion: BlockTemplate, ImageDigest: p.Manifest.ImageDigest, Resources: p.Manifest.Budget.Effective}
	plan, err := p.Plan(agent.StoreScope{InstallationID: "installation", TenantID: "tenant", HostID: "host", EndpointIdentity: p.Manifest.EndpointIdentity}, s)
	if err != nil {
		t.Fatal(err)
	}
	if plan.HostConfig.NanoCPUs != 1000000000 || plan.HostConfig.Memory != 1<<30 || plan.HostConfig.MemorySwap != 1<<30 || plan.HostConfig.CgroupParent != hostCgroupUnit(plan.Name) {
		t.Fatal("effective overhead charged to guest instead of independent host slice")
	}
	if s.Resources != p.Manifest.Budget.Effective {
		t.Fatal("host journal reservation changed")
	}
}

func TestConfiguredOrActiveSliceIsNeverEmptyCapacity(t *testing.T) {
	missing := map[string]string{"LoadState": "loaded", "ActiveState": "inactive", "Transient": "no", "ControlGroup": "", "FragmentPath": "", "SourcePath": "", "DropInPaths": ""}
	if !cgroupUnitMissing(missing) {
		t.Fatal("systemd implicit inactive slice misclassified")
	}
	for key, value := range map[string]string{"ActiveState": "active", "Transient": "yes", "ControlGroup": "/foreign", "FragmentPath": "/etc/systemd/system/foreign.slice", "DropInPaths": "/run/systemd/system/foreign.slice.d/override.conf", "SourcePath": "/foreign"} {
		copy := map[string]string{}
		for k, v := range missing {
			copy[k] = v
		}
		copy[key] = value
		if cgroupUnitMissing(copy) {
			t.Fatal("foreign configured/active slice treated as absent", key)
		}
	}
}
