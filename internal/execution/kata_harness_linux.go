//go:build linux && runnerd_qualification

package execution

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

func QualificationPhase(phase string) bool {
	for _, value := range []string{"none", "command-reply-loss", "before-command-ack", "after-command-ack", "issuance-reply-loss", "create-reply-loss", "start-reply-loss", "after-runtime-exit", "before-native-event-ack", "event-reply-loss", "before-runtime-remove", "remove-verification-loss"} {
		if phase == value {
			return true
		}
	}
	parts := strings.Split(phase, ":")
	if len(parts) != 3 || parts[0] != "journal" {
		return false
	}
	method, stage := false, false
	for _, value := range []string{"AcceptCommand", "PutStartIntent", "RecordObservation", "RequireCleanup", "CompleteCleanup", "AckEvents"} {
		method = method || parts[1] == value
	}
	for _, value := range []string{"before-commit", "after-commit", "after-anchor"} {
		stage = stage || parts[2] == value
	}
	return method && stage
}

// RunKataQualification drives the real controller. Killing/restarting this
// process retains its real journal and sealed keys. An external coordinator
// must persist barrier observations before power removal; this code never reboots.
func RunKataQualification(ctx context.Context, configFile, bindingFile, pin, control, phase, executionID string) error {
	if !QualificationPhase(phase) || os.Geteuid() == 0 || !strings.HasPrefix(control, "/var/tmp/runnerd09-lifecycle-") {
		return ErrReconcile
	}
	private, err := hostfs.OpenState(control)
	if err != nil {
		return err
	}
	defer private.Close()
	raw, err := hostfs.ReadPrivate(configFile, config.MaxConfigBytes)
	if err != nil {
		return err
	}
	c, err := config.Parse(raw)
	if err != nil {
		return err
	}
	if c.Execution == nil || c.Execution.Kata == nil || !c.Execution.Enabled {
		return ErrReconcile
	}
	raw, err = hostfs.ReadPrivate(bindingFile, 65536)
	if err != nil {
		return err
	}
	var binding katalinux.LabBinding
	if json.Unmarshal(raw, &binding) != nil {
		return ErrReconcile
	}
	if executionID == "" {
		executionID = "execution-" + binding.CaseID
	}
	if !strings.HasPrefix(executionID, "execution-"+binding.CaseID) {
		return ErrReconcile
	}
	policy, err := NewPolicyFile(c.Execution.PolicyFile)
	if err != nil {
		return err
	}
	store, err := journal.OpenRecovery(ctx, c.StateDir, journal.Options{ReservationLimits: policy.Get().Limits()})
	if err != nil {
		return err
	}
	defer store.Close()
	fault := &labFault{control: control, phase: phase}
	if data, e := hostfs.ReadPrivate(filepath.Join(control, "fault.json"), 65536); e == nil {
		var previous struct {
			Phase string `json:"phase"`
		}
		if json.Unmarshal(data, &previous) != nil || previous.Phase != phase {
			return ErrReconcile
		}
		fault.fired.Store(true)
	} else if _, e = os.Lstat(filepath.Join(control, "fault.json")); !os.IsNotExist(e) {
		return ErrReconcile
	}
	err = store.SetQualificationFaultBeforeRun(func(stage string) error {
		parts := strings.Split(phase, ":")
		if len(parts) != 3 || parts[0] != "journal" || parts[2] != stage {
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
				return nil
			}
		}
	})
	if err != nil {
		return err
	}
	controller, closeController, err := OpenQualification(c, configFile, store, policy, func() bool { _, e := os.Stat(filepath.Join(control, "drain")); return e == nil }, pin, binding)
	if err != nil {
		return err
	}
	defer closeController()
	controller.Runtime = &labRuntime{Runtime: controller.Runtime, fault: fault}
	controller.Remote = &labRemote{Remote: controller.Remote, fault: fault}
	if err = fault.metadata("harness.json", map[string]any{"version": "runnerd09-lifecycle-harness-v1", "phase": phase, "caseId": binding.CaseID, "qualified": false, "productionAdmission": false, "scope": "real controller/SQLite/Docker/root observer; isolated fixture authority"}); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	stopped := make(chan struct{})
	go func() { defer close(stopped); done <- controller.Run(ctx) }()
	defer func() { cancel(); <-stopped }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			return err
		case <-ticker.C:
			health := store.Health(ctx)
			rows, e := store.Executions(ctx, agent.ExecutionCursor{}, 100)
			if e != nil {
				return e
			}
			summaries := []map[string]any{}
			for _, row := range rows {
				summaries = append(summaries, map[string]any{"executionId": row.Identity.ExecutionID, "generation": row.Identity.Generation, "state": row.State, "cleanupPending": row.CleanupPending, "lastSequence": row.LastSequence, "ackSequence": row.AckSequence})
				if row.Identity.ExecutionID == executionID && row.State == "cleaned" && !row.CleanupPending && row.LastSequence != "0" && row.LastSequence == row.AckSequence {
					if _, exists := os.Lstat(filepath.Join(control, "evidence.json")); os.IsNotExist(exists) {
						proof, proofErr := controller.KataEvidence(ctx, row.Identity.ExecutionID, row.Identity.Generation)
						if proofErr == nil {
							if err = fault.metadata("evidence.json", proof); err != nil {
								return err
							}
						}
					}
				}
			}
			if err = fault.metadata("status.json", map[string]any{"ready": health.Ready, "reason": health.Reason, "controller": controller.Status(), "executions": summaries}); err != nil {
				return err
			}
			if _, err = os.Stat(filepath.Join(control, "stop")); err == nil {
				cancel()
				return <-done
			}
		}
	}
}
