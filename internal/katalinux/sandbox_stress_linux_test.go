//go:build linux

package katalinux

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Run only in an explicitly marked disposable host under a systemd unit with
// RuntimeMaxSec, CPUQuota and KillMode=control-group. Workers/files belong only
// to this test. A missed budget fails qualification; it never skips ref checks.
func TestNativeSandboxBusyHostCleanupBudget(t *testing.T) {
	if os.Getenv("RUNNERD09_SANDBOX_STRESS") != "1" {
		t.Skip("explicit disposable-host cleanup stress opt-in required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root disposable host required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal("disposable-host marker required")
	}
	parameter := func(name string, fallback, min, max int) int {
		t.Helper()
		if raw := os.Getenv(name); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < min || value > max {
				t.Fatal("invalid bounded stress parameter", name)
			}
			return value
		}
		return fallback
	}
	files := parameter("RUNNERD09_SANDBOX_STRESS_FILES", 1000, 1000, 4093)
	workers := parameter("RUNNERD09_SANDBOX_STRESS_WORKERS", 32, 8, 64)
	backgroundStarted := time.Now()
	sandboxStressWorkers(t, workers)
	backgroundSetup := time.Since(backgroundStarted)
	for _, held := range []bool{false, true} {
		t.Run(fmt.Sprintf("retained-reference=%t", held), func(t *testing.T) {
			scenarioStarted := time.Now()
			p, root, id, stamp := sandboxNative(t)
			for i := 0; i < files; i++ {
				if err := os.WriteFile(filepath.Join(root, id, "rw", fmt.Sprintf("file-%04d", i)), []byte("owned"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			heldPath := filepath.Join(root, id, "rw", "hosts")
			var releaseReference func()
			if held {
				_, _, releaseReference = startSurvivingWorkerControlled(t, "mmap", heldPath)
			}
			requestStarted := time.Now()
			var cpuBefore syscall.Rusage
			_ = syscall.Getrusage(syscall.RUSAGE_SELF, &cpuBefore)
			var memoryBefore runtime.MemStats
			runtime.ReadMemStats(&memoryBefore)
			ctx, cancel := context.WithTimeout(t.Context(), 110*time.Second)
			defer cancel()
			metrics := &sandboxMetrics{}
			ctx = context.WithValue(ctx, sandboxMetricsKey{}, metrics)
			var guards atomic.Int64
			guardMode := os.Getenv("RUNNERD09_SANDBOX_STRESS_GUARDS")
			guard := func() error { guards.Add(1); return nil }
			var snapshot sandboxGuardSnapshot
			if guardMode == "production-readonly" {
				actualGuard := sandboxProductionStressGuard(t, ctx, p, root, id, &snapshot)
				guard = func() error { guards.Add(1); return actualGuard() }
			} else if guardMode != "" {
				t.Fatal("unknown stress guard mode")
			}
			started := time.Now()
			err := p.removeSandboxResidue(ctx, id, []SandboxDirectory{stamp}, guard)
			elapsed := time.Since(started)
			requestElapsed := time.Since(requestStarted)
			var cpuAfter syscall.Rusage
			_ = syscall.Getrusage(syscall.RUSAGE_SELF, &cpuAfter)
			var memoryAfter runtime.MemStats
			runtime.ReadMemStats(&memoryAfter)
			_, remaining := os.Lstat(filepath.Join(root, id))
			result, _ := json.Marshal(map[string]any{"scope": "synthetic-native-runtime-metadata-stress", "files": files + 3, "timings": metrics, "guardMode": guardMode, "backgroundWorkers": workers, "namespaceWorkers": 4, "cpuBusyWorkers": 4, "retainedReference": held, "elapsedMillis": elapsed.Milliseconds(), "requestElapsedMillis": requestElapsed.Milliseconds(), "backgroundSetupMillis": backgroundSetup.Milliseconds(), "metadataSetupMillis": requestStarted.Sub(scenarioStarted).Milliseconds(), "endToEndMillis": (backgroundSetup + time.Since(scenarioStarted)).Milliseconds(), "referenceRejection": errors.Is(err, errSandboxReferenceHeld), "guardSetupMillis": started.Sub(requestStarted).Milliseconds(), "allocatedBytes": memoryAfter.TotalAlloc - memoryBefore.TotalAlloc, "allocations": memoryAfter.Mallocs - memoryBefore.Mallocs, "cpuMicros": cpuAfter.Utime.Nano()/1000 + cpuAfter.Stime.Nano()/1000 - cpuBefore.Utime.Nano()/1000 - cpuBefore.Stime.Nano()/1000, "budgetMillis": 110000, "guardCalls": guards.Load(), "timedOut": ctx.Err() != nil, "removed": os.IsNotExist(remaining), "productionQualified": false})
			t.Log(string(result))
			if ctx.Err() != nil || backgroundSetup+time.Since(scenarioStarted) >= 110*time.Second {
				t.Error("cleanup exceeded unchanged end-to-end budget; retain qualification gate", err)
			}
			if held {
				if !errors.Is(err, errSandboxReferenceHeld) || remaining != nil {
					t.Error("retained reference did not produce explicit bounded rejection", err, remaining)
				}
				if _, err := os.Stat(heldPath); err != nil {
					t.Fatal("held inode removed", err)
				}
				releaseReference()
				resumeStarted := time.Now()
				resume, cancelResume := context.WithTimeout(t.Context(), 110*time.Second)
				defer cancelResume()
				resumeMetrics := &sandboxMetrics{}
				resume = context.WithValue(resume, sandboxMetricsKey{}, resumeMetrics)
				resumeGuard := func() error { return nil }
				if guardMode == "production-readonly" {
					var close func()
					resumeGuard, close, err = snapshot.open(resume, id)
					if err != nil {
						t.Fatal("fresh original-peer guard unavailable for resume", err)
					}
					defer close()
				}
				resumeErr := p.removeSandboxResidue(resume, id, []SandboxDirectory{stamp}, resumeGuard)
				_, stillPresent := os.Lstat(filepath.Join(root, id))
				row, _ := json.Marshal(map[string]any{"scope": "metadata-resume-after-reference-release", "elapsedMillis": time.Since(resumeStarted).Milliseconds(), "timedOut": resume.Err() != nil, "removed": os.IsNotExist(stillPresent), "timings": resumeMetrics, "productionQualified": false})
				t.Log(string(row))
				if resumeErr != nil || !os.IsNotExist(stillPresent) {
					t.Error("fresh cleanup after reference release incomplete", resumeErr, stillPresent)
				}
			} else if err != nil || !os.IsNotExist(remaining) {
				t.Error("unreferenced metadata not removed within budget", err, remaining)
			}
		})
	}
}

func sandboxStressWorkers(t *testing.T, workers int) {
	t.Helper()
	unrelated := t.TempDir()
	mapping := filepath.Join(unrelated, "mapped-unrelated")
	if err := os.WriteFile(mapping, make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < workers; i++ {
		mode, target := "mmap", mapping
		if i < 4 {
			mode, target = "namespace-hidden-bind", filepath.Join(unrelated, fmt.Sprintf("namespace-%d", i))
			if err := os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
		} else if i < 8 {
			mode = "busy-mmap"
		}
		startSurvivingWorker(t, mode, target)
	}
}
