//go:build linux && runnerd_qualification

package execution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
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
	if err == nil {
		dir, e := os.Open(f.control)
		if e != nil {
			return e
		}
		err = dir.Sync()
		err = errors.Join(err, dir.Close())
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
	if err := f.metadata("barrier.json", map[string]any{"phase": phase, "state": "waiting", "at": time.Now().UTC().Format(time.RFC3339Nano)}); err != nil {
		return err
	}
	defer func() {
		_ = f.metadata("barrier.json", map[string]any{"phase": phase, "state": "returned", "at": time.Now().UTC().Format(time.RFC3339Nano)})
	}()
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

func (r *labRuntime) VerifyNetworkDetached(ctx context.Context, id, network string) error {
	if r.fault.offline() {
		return dockerengine.ErrUnavailable
	}
	checker, ok := r.Runtime.(interface {
		VerifyNetworkDetached(context.Context, string, string) error
	})
	if !ok {
		return dockerengine.ErrUnavailable
	}
	return checker.VerifyNetworkDetached(ctx, id, network)
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
	if errors.Is(err, dockerengine.ErrConflict) {
		if engine, ok := r.Runtime.(*dockerengine.Engine); ok {
			_ = r.fault.metadata("runtime-conflict.json", engine.QualificationDiff(ctx, id, p))
		}
	}
	if err == nil && o.State == "exited" {
		if err = r.fault.barrier(ctx, "after-runtime-exit"); err != nil {
			return o, err
		}
	}
	return o, err
}
func (r *labRuntime) Ensure(ctx context.Context, p dockerengine.Plan, claim func() error) (dockerengine.Object, error) {
	o, err := r.Runtime.Ensure(ctx, p, claim)
	if errors.Is(err, dockerengine.ErrConflict) {
		if engine, ok := r.Runtime.(*dockerengine.Engine); ok {
			_ = r.fault.metadata("runtime-conflict.json", engine.QualificationDiff(ctx, p.Name, p))
		}
	}
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
