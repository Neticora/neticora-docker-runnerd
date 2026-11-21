package service

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/connectionrecovery"
	"github.com/Neticora/neticora-docker-runnerd/internal/control"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

// Run defaults to the drained foundation. Explicit execution configuration wires
// the controller; shutdown cancels its operations without stopping workloads.
func Run(ctx context.Context, c config.Config, socket string) error {
	var policy *execution.PolicyFile
	options := journal.Options{}
	executing := c.Execution != nil && c.Execution.Enabled
	if executing {
		var e error
		policy, e = execution.NewPolicyFile(c.Execution.PolicyFile)
		if e != nil {
			return e
		}
		options.ReservationLimits = policy.Get().Limits()
	}
	// A reboot must never turn loss of the original journal into a fresh store.
	if !executing && c.Connection != nil {
		credentials, key, e := execution.ReadCredentials(c.CredentialFile)
		clear(key)
		if e != nil {
			return e
		}
		boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if e != nil {
			return e
		}
		if strings.TrimSpace(string(boot)) != credentials.BootID {
			for _, name := range []string{"journal.db", "recovery.anchor.json"} {
				if _, e = os.Lstat(filepath.Join(c.StateDir, name)); e != nil {
					connectionrecovery.StartupFailure(c, "original-journal-missing")
					return errors.New("connection recovery blocked: original journal or anchor missing; retain enrollment and restore original recovery evidence")
				}
			}
		}
	}
	store, err := journal.OpenRecovery(ctx, c.StateDir, options)
	if err != nil {
		connectionrecovery.StartupFailure(c, "journal-integrity-unavailable")
		return err
	}
	defer store.Close()
	var draining atomic.Bool
	drainFile := filepath.Join(c.StateDir, "admission.drained")
	_, drainErr := os.Lstat(drainFile)
	if drainErr != nil && !os.IsNotExist(drainErr) {
		return errors.New("drain state unavailable")
	}
	draining.Store(!executing || drainErr == nil)
	controllerCtx, stopController := context.WithCancel(ctx)
	defer stopController()
	connection := &connectionStatus{state: "disabled"}
	if !executing && c.Connection != nil {
		done := make(chan struct{})
		go func() {
			defer close(done)
			connect(controllerCtx, c, connection, func(ctx context.Context) (bool, error) {
				health := store.Health(ctx)
				if health.Reason != "reconciliation-required" && health.Reason != "ready" {
					return false, agent.ErrRecoveryRequired
				}
				rows, err := store.Incomplete(ctx, agent.ExecutionCursor{}, 1)
				return err == nil && len(rows) == 0, err
			}, store)
		}()
		defer func() { stopController(); <-done }()
	}
	var controller *execution.Controller
	recoveryReason := ""
	if executing {
		var cleanup func()
		controller, cleanup, err = execution.Open(c, store, policy, draining.Load)
		if errors.Is(err, agent.ErrRecoveryRequired) {
			draining.Store(true)
			recoveryReason = "operator-peer-recovery-required"
			if err = persistDrain(drainFile); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			defer cleanup()
		}
	}
	server, err := control.Listen(socket, func() control.Snapshot {
		state := "not-ready"
		if draining.Load() {
			state = "drained"
		}
		healthCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		health := store.Health(healthCtx)
		if executing && !draining.Load() {
			state = "reconciling"
			if health.Ready {
				state = "ready"
			}
		}
		reason := recoveryReason
		if controller != nil {
			reason = controller.Status()
		}
		platform, lastHeartbeat := connection.get()
		inventory, inventoryFresh := connection.inventoryStatus()
		recovery := connection.recoveryStatus()
		readiness := execution.Readiness{QualificationState: "unqualified", DispatchBlockers: []string{"execution-disabled"}}
		if controller != nil {
			readiness = controller.Readiness(time.Now())
		}
		if executing && controller == nil {
			readiness.DispatchBlockers = []string{reason}
		}
		if !health.Ready {
			readiness.DispatchBlockers = append(readiness.DispatchBlockers, health.Reason)
		}
		admitted := executing && !draining.Load() && health.Ready && len(readiness.DispatchBlockers) == 0
		if executing && !admitted {
			state = "blocked"
			if draining.Load() {
				state = "drained"
			}
		}
		return control.Snapshot{QualificationState: readiness.QualificationState, DispatchBlockers: readiness.DispatchBlockers, PlatformAdmissionEnabled: readiness.PlatformAdmissionEnabled, ConnectionRecoveryOperationID: recovery.operation, ConnectionRecoveryReason: recovery.reason, ObservationSessionEpoch: recovery.epoch, ObservationBootID: recovery.boot, ObservationEndpointIdentity: recovery.endpoint, InventoryState: inventory.State, InventoryGeneration: inventory.Generation, InventoryObservedAt: inventory.ObservedAt, InventoryFresh: inventoryFresh, Platform: platform, LastHeartbeat: lastHeartbeat, ExecutionReason: reason, ExecutionEnabled: executing, State: state, AdmissionEnabled: admitted, RuntimeQualified: readiness.RuntimeQualified, RecoveryReady: health.Ready, RecoveryReason: health.Reason}
	}, func() {
		draining.Store(true)
	}, func(event string) { log.Print(event) })
	if err != nil {
		return err
	}
	defer server.Close()
	server.SetDurableDrain(func() error { draining.Store(true); return persistDrain(drainFile) })
	server.ExposeExecutions(func(ctx context.Context, afterID, afterGeneration string) (any, error) {
		rows, e := store.Incomplete(ctx, agent.ExecutionCursor{ExecutionID: afterID, Generation: afterGeneration}, 10)
		if e != nil {
			return nil, e
		}
		out := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			var ref struct {
				ResourceID string `json:"resourceId"`
			}
			_ = json.Unmarshal(row.RuntimeRef, &ref)
			out = append(out, map[string]any{"executionId": row.Identity.ExecutionID, "generation": row.Identity.Generation, "state": row.State, "cleanupPending": row.CleanupPending, "lastSequence": row.LastSequence, "ackSequence": row.AckSequence, "resourceId": ref.ResourceID})
		}
		result := map[string]any{"executions": out}
		if len(rows) == 10 {
			last := rows[len(rows)-1]
			result["nextCursor"] = map[string]string{"executionId": last.Identity.ExecutionID, "generation": last.Identity.Generation}
		}
		return result, nil
	})
	if controller != nil {
		done := make(chan struct{})
		go func() {
			defer close(done)
			if e := controller.Run(controllerCtx); e != nil {
				draining.Store(true)
				log.Print("execution controller stopped; admission fenced")
			}
		}()
		defer func() { stopController(); <-done }()
	}
	result := make(chan error, 1)
	go func() { result <- server.Serve() }()
	select {
	case err = <-result:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr := server.Shutdown(shutdown)
		if shutdownErr != nil {
			closeErr := server.Close()
			serveErr := <-result
			return errors.Join(errors.New("control shutdown failed"), shutdownErr, closeErr, serveErr)
		}
		return <-result
	}
}

func persistDrain(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		_, err = hostfs.ReadPrivate(path, 0)
		return err
	}
	if err != nil {
		return errors.New("cannot persist drain fence")
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("cannot sync drain fence")
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("cannot sync drain directory")
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return errors.New("cannot sync drain directory")
	}
	return nil
}
