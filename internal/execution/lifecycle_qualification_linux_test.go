//go:build linux && runnerd_qualification

package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

// labFault decorates the real store, runtime and remote. No synthetic provider,
// authority, image verifier, runtime objects or cleanup facts are substituted.
type labFault struct {
	control, phase       string
	fired                atomic.Bool
	partitionAfterRemove atomic.Bool
}

func (f *labFault) metadata(name string, value any) error {
	file, err := os.CreateTemp(f.control, ".metadata-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	err = json.NewEncoder(file).Encode(value)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(file.Name(), filepath.Join(f.control, name))
	}
	return err
}

func (f *labFault) hit(phase string) bool {
	if phase != f.phase || !f.fired.CompareAndSwap(false, true) {
		return false
	}
	if f.metadata("fault.json", map[string]any{"phase": phase, "at": time.Now().UTC().Format(time.RFC3339Nano)}) != nil {
		return false
	}
	return true
}

func (f *labFault) barrier(ctx context.Context, phase string) error {
	if !f.hit(phase) {
		return nil
	}
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	for {
		if _, err := os.Stat(filepath.Join(f.control, "continue")); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("qualification barrier deadline")
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (f *labFault) offline() bool {
	_, err := os.Stat(filepath.Join(f.control, "partition"))
	if err == nil {
		return true
	}
	if f.partitionAfterRemove.Load() {
		_, err = os.Stat(filepath.Join(f.control, "continue"))
		return err != nil
	}
	return false
}

type labRuntime struct {
	Runtime
	fault *labFault
}

func (r *labRuntime) Probe(ctx context.Context) (string, error) {
	if r.fault.offline() {
		return "", dockerengine.ErrUnavailable
	}
	return r.Runtime.Probe(ctx)
}
func (r *labRuntime) Inventory(ctx context.Context) ([]string, error) {
	if r.fault.offline() {
		return nil, dockerengine.ErrUnavailable
	}
	return r.Runtime.Inventory(ctx)
}
func (r *labRuntime) Inspect(ctx context.Context, id string, p dockerengine.Plan) (dockerengine.Object, error) {
	if r.fault.offline() {
		return dockerengine.Object{}, dockerengine.ErrUnavailable
	}
	o, err := r.Runtime.Inspect(ctx, id, p)
	if err == nil && o.State == "exited" {
		if err = r.fault.barrier(ctx, "after-runtime-exit"); err != nil {
			return o, err
		}
	}
	return o, err
}
func (r *labRuntime) Ensure(ctx context.Context, p dockerengine.Plan, claim func() error) (dockerengine.Object, error) {
	o, err := r.Runtime.Ensure(ctx, p, claim)
	if err == nil && r.fault.hit("create-reply-loss") {
		return dockerengine.Object{}, dockerengine.ErrUnavailable
	}
	return o, err
}
func (r *labRuntime) Start(ctx context.Context, id string, p dockerengine.Plan, authorize func() error) (dockerengine.Object, error) {
	o, err := r.Runtime.Start(ctx, id, p, authorize)
	if err == nil && r.fault.hit("start-reply-loss") {
		return dockerengine.Object{}, dockerengine.ErrUnavailable
	}
	return o, err
}
func (r *labRuntime) Remove(ctx context.Context, id string, p dockerengine.Plan) error {
	if err := r.fault.barrier(ctx, "before-runtime-remove"); err != nil {
		return err
	}
	err := r.Runtime.Remove(ctx, id, p)
	if err == nil && r.fault.hit("remove-verification-loss") {
		r.fault.partitionAfterRemove.Store(true)
		return dockerengine.ErrUnavailable
	}
	return err
}

type labRemote struct {
	Remote
	fault *labFault
}

func (r *labRemote) Recovery(ctx context.Context, c []agent.ExecutionCursor) (protocol.RecoveryState, error) {
	if r.fault.offline() {
		return protocol.RecoveryState{}, ErrReconcile
	}
	return r.Remote.Recovery(ctx, c)
}
func (r *labRemote) Commands(ctx context.Context) ([]json.RawMessage, error) {
	if r.fault.offline() {
		return nil, ErrReconcile
	}
	commands, err := r.Remote.Commands(ctx)
	if err == nil && len(commands) > 0 && r.fault.hit("command-reply-loss") {
		return nil, ErrReconcile
	}
	return commands, err
}
func (r *labRemote) Ack(ctx context.Context, receipt agent.Receipt) error {
	if r.fault.offline() {
		return ErrReconcile
	}
	if err := r.fault.barrier(ctx, "before-command-ack"); err != nil {
		return err
	}
	err := r.Remote.Ack(ctx, receipt)
	if err == nil {
		err = r.fault.barrier(ctx, "after-command-ack")
	}
	return err
}
func (r *labRemote) Inventory(ctx context.Context, m protocol.Outbound) error {
	if r.fault.offline() {
		return ErrReconcile
	}
	return r.Remote.Inventory(ctx, m)
}
func (r *labRemote) Events(ctx context.Context, m protocol.Outbound) ([]protocol.EventAck, error) {
	if r.fault.offline() {
		return nil, ErrReconcile
	}
	acks, err := r.Remote.Events(ctx, m)
	if err == nil && len(acks) > 0 {
		if r.fault.hit("event-reply-loss") {
			return nil, ErrReconcile
		}
		if err = r.fault.barrier(ctx, "before-native-event-ack"); err != nil {
			return nil, err
		}
	}
	return acks, err
}
func (r *labRemote) Start(ctx context.Context, m protocol.Outbound) (protocol.StartResponse, error) {
	if r.fault.offline() {
		return protocol.StartResponse{}, ErrReconcile
	}
	response, err := r.Remote.Start(ctx, m)
	if err == nil && r.fault.hit("issuance-reply-loss") {
		return protocol.StartResponse{}, ErrReconcile
	}
	return response, err
}
func (r *labRemote) Admission(ctx context.Context, s protocol.ExecutionSpec) error {
	if r.fault.offline() {
		return ErrReconcile
	}
	return r.Remote.Admission(ctx, s)
}
func (r *labRemote) Heartbeat(ctx context.Context, generation string) error {
	if r.fault.offline() {
		return ErrReconcile
	}
	return r.Remote.Heartbeat(ctx, generation)
}

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
