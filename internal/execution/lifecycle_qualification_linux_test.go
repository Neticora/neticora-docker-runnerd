//go:build linux && runnerd_qualification

package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

func TestRunnerd08LiveLifecycle(t *testing.T) {
	if os.Getenv("RUNNERD08_LIVE_QUALIFICATION") != "1" {
		t.Skip("explicit dedicated-host live qualification required")
	}
	if os.Geteuid() == 0 {
		t.Fatal("real non-root service identity required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal("disposable lab required")
	}
	control := os.Getenv("RUNNERD08_CONTROL")
	if !strings.HasPrefix(control, "/var/tmp/runnerd08-lifecycle-") || filepath.Clean(control) != control {
		t.Fatal("private lab control directory required")
	}
	private, err := hostfs.OpenState(control)
	if err != nil {
		t.Fatal("private control permissions")
	}
	defer private.Close()
	phase := os.Getenv("RUNNERD08_PHASE")
	allowed := map[string]bool{"none": true, "command-reply-loss": true, "before-command-ack": true, "after-command-ack": true, "issuance-reply-loss": true, "create-reply-loss": true, "start-reply-loss": true, "after-runtime-exit": true, "before-native-event-ack": true, "event-reply-loss": true, "before-runtime-remove": true, "remove-verification-loss": true}
	for _, method := range []string{"AcceptCommand", "PutStartIntent", "RecordObservation", "RequireCleanup", "CompleteCleanup", "AckEvents"} {
		for _, stage := range []string{"before-commit", "after-commit", "after-anchor"} {
			allowed["journal:"+method+":"+stage] = true
		}
	}
	if !allowed[phase] {
		t.Fatal("unknown qualification phase")
	}
	raw, err := hostfs.ReadPrivate(os.Getenv("RUNNERD08_CONFIG"), config.MaxConfigBytes)
	if err != nil {
		t.Fatal("private execution configuration required")
	}
	c, err := config.Parse(raw)
	clear(raw)
	if err != nil || c.Execution == nil || !c.Execution.Enabled || c.RuntimeEndpoint != "unix:///run/runnerd07-docker.sock" || c.ControlPlaneURL != "https://platform.scvcluster.neticora.com/api/v1/runner-hosts" {
		t.Fatal("explicit Vagrant execution tuple required")
	}
	policy, err := NewPolicyFile(c.Execution.PolicyFile)
	if err != nil {
		t.Fatal("invalid protected policy")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	store, err := journal.OpenRecovery(ctx, c.StateDir, journal.Options{ReservationLimits: policy.Get().Limits()})
	if err != nil {
		t.Fatal("journal unavailable; preserved for operator recovery")
	}
	defer store.Close()
	fault := &labFault{control: control, phase: phase}
	err = store.SetQualificationFaultBeforeRun(func(stage string) error {
		if !strings.HasPrefix(phase, "journal:") {
			return nil
		}
		parts := strings.Split(phase, ":")
		if len(parts) != 3 || parts[2] != stage {
			return nil
		}
		pc := make([]uintptr, 32)
		frames := runtime.CallersFrames(pc[:runtime.Callers(2, pc)])
		for {
			frame, more := frames.Next()
			if strings.Contains(frame.Function, "journal.(*SQLiteStore)."+parts[1]) {
				return fault.barrier(ctx, phase)
			}
			if !more {
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	controller, cleanup, err := Open(c, store, policy, func() bool { _, e := os.Stat(filepath.Join(c.StateDir, "admission.drained")); return e == nil })
	if err != nil {
		t.Fatal("real controller unavailable")
	}
	defer cleanup()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(bytes)
	clear(bytes)
	version := "runnerd08-qualification-" + hex.EncodeToString(hash[:])[:24]
	controller.Remote.(*HostRemote).Version = version
	controller.Runtime = &labRuntime{Runtime: controller.Runtime, fault: fault}
	controller.Remote = &labRemote{Remote: controller.Remote, fault: fault}
	if err = fault.metadata("identity.json", map[string]any{"agentVersion": version, "binarySha256": hex.EncodeToString(hash[:]), "phase": phase, "scope": "tagged lab controller; real Docker, SQLite and authenticated platform"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("live controller stopped; journal retained")
			}
			return
		case <-ticker.C:
			if _, err := os.Stat(filepath.Join(control, "stop")); err == nil {
				cancel()
			}
			readCtx, stop := context.WithTimeout(ctx, 250*time.Millisecond)
			health := store.Health(readCtx)
			rows, readErr := store.Incomplete(readCtx, agent.ExecutionCursor{}, 10)
			stop()
			executions := []map[string]any{}
			for _, row := range rows {
				executions = append(executions, map[string]any{"executionId": row.Identity.ExecutionID, "generation": row.Identity.Generation, "state": row.State, "lastSequence": row.LastSequence, "ackSequence": row.AckSequence, "cleanupPending": row.CleanupPending})
			}
			if err := fault.metadata("status.json", map[string]any{"ready": health.Ready, "reason": health.Reason, "controller": controller.Status(), "readFailed": readErr != nil, "executions": executions}); err != nil {
				cancel()
				<-done
				t.Fatal("private status write failed")
			}
		}
	}
}
