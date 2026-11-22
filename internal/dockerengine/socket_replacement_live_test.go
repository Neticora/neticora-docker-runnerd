//go:build linux && runnerd_docker

package dockerengine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// An isolated real dockerd starts with two private Unix listeners. Replacing one
// path with its other listener changes the inode without restarting the daemon.
// The coordinator never changes the system Docker service or its configuration.
func TestRealDockerSocketOnlyReplacementSameDaemon(t *testing.T) {
	socketLab(t)
	if os.Geteuid() != 0 {
		t.Fatal("root disposable socket-replacement coordinator required")
	}
	control := os.Getenv("RUNNERD_SOCKET_ONLY_CONTROL")
	if !strings.HasPrefix(control, "/var/tmp/runnerd-socket-only-") || filepath.Clean(control) != control {
		t.Fatal("private bounded qualification control required")
	}
	path := filepath.Join(control, "selected.sock")
	replacement := filepath.Join(control, "alternate.sock")
	first, err := os.Lstat(path)
	if err != nil || first.Mode()&os.ModeSocket == 0 {
		t.Fatal("first listener missing", err)
	}
	other, err := os.Lstat(replacement)
	if err != nil || other.Mode()&os.ModeSocket == 0 || os.SameFile(first, other) {
		t.Fatal("distinct replacement listener missing", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var invalidations atomic.Int32
	original, err := OpenReadOnly("unix://"+path, "socket-only-qualification", func() { invalidations.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	before, err := original.Probe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	original.mu.Lock()
	processBefore, daemonBefore := original.peer, original.daemonID
	original.mu.Unlock()
	if err = os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	afterStat, err := os.Lstat(path)
	if err != nil || os.SameFile(first, afterStat) {
		t.Fatal("socket path was not replaced", err)
	}
	if _, err = original.Probe(ctx); !errors.Is(err, ErrContinuity) || !errors.Is(err, ErrUnavailable) || invalidations.Load() == 0 {
		t.Fatal("path replacement did not invalidate the original observation", err)
	}
	fresh, err := OpenReadOnly("unix://"+path, "socket-only-qualification", func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	after, err := fresh.Probe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fresh.mu.Lock()
	processAfter, daemonAfter := fresh.peer, fresh.daemonID
	fresh.mu.Unlock()
	if processBefore != processAfter || daemonBefore != daemonAfter || before != after {
		t.Fatal("same-process socket replacement was mislabeled as a daemon restart")
	}
	// A successful fresh observation is not execution or recovery authorization.
	for _, mutate := range []func() error{
		func() error { _, e := fresh.Ensure(ctx, Plan{}, func() error { return nil }); return e },
		func() error { _, e := fresh.Start(ctx, "not-owned", Plan{}, func() error { return nil }); return e },
		func() error { return fresh.Stop(ctx, "not-owned", Plan{}) },
		func() error { return fresh.Remove(ctx, "not-owned", Plan{}) },
	} {
		if err = mutate(); !errors.Is(err, ErrRecoveryApprovalRequired) {
			t.Fatal("socket observation granted mutation authority", err)
		}
	}
	data, _ := json.Marshal(map[string]any{"realDockerDaemon": true, "daemonProcessBefore": processBefore, "daemonProcessAfter": processAfter, "daemonIdBefore": daemonBefore, "daemonIdAfter": daemonAfter, "endpointBefore": before, "endpointAfter": after, "socketInodeBefore": first.Sys().(*syscall.Stat_t).Ino, "socketInodeAfter": afterStat.Sys().(*syscall.Stat_t).Ino, "originalObservationInvalidated": true, "invalidations": invalidations.Load(), "readOnlyRecoveryMutationsRejected": true})
	if err = os.WriteFile(filepath.Join(control, "same-daemon-evidence.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
}
