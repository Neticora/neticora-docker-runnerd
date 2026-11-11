//go:build linux

package katalinux

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

type sandboxCrashFixture struct {
	Directory string                `json:"directory"`
	ID        string                `json:"id"`
	Stamp     SandboxDirectory      `json:"stamp"`
	Guard     *sandboxGuardSnapshot `json:"guard,omitempty"`
}

// Test-only subprocess; no alternate production admission or cleanup path.
func TestSandboxCleanupProcessChild(t *testing.T) {
	file := os.Getenv("RUNNERD09_SANDBOX_CHILD_FIXTURE")
	if file == "" {
		t.Skip("native crash-test child only")
	}
	raw, err := hostfs.ReadPrivate(file, 128<<10)
	var fixture sandboxCrashFixture
	if err != nil || json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("protected original fixture required", err)
	}
	p := &Profile{Manifest: Manifest{Version: MultiBlockVersion, SandboxRoots: []string{fixture.Directory}}}
	p.Manifest.Storage.Runtime.Root = fixture.Directory
	p.Manifest.Storage.Runtime.Device = fixture.Stamp.Device
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	actualGuard := func() error { return nil }
	if fixture.Guard != nil {
		if fixture.Guard.Profile.Manifest.Qualified || !fixture.Guard.Evidence.Prepared {
			t.Fatal("explicit unqualified prepared-state guard fixture required")
		}
		p = &fixture.Guard.Profile
		var close func()
		actualGuard, close, err = fixture.Guard.open(ctx, fixture.ID)
		if err != nil {
			t.Fatal("original runtime/ownership guard unavailable", err)
		}
		defer close()
	}
	guards := 0
	err = p.removeSandboxResidue(ctx, fixture.ID, []SandboxDirectory{fixture.Stamp}, func() error {
		if err := actualGuard(); err != nil {
			return err
		}
		guards++
		if os.Getenv("RUNNERD09_SANDBOX_CHILD_PHASE") == "pause" && guards == 3 {
			root, err := hostfs.OpenState(fixture.Directory)
			if err != nil {
				return err
			}
			defer root.Close()
			f, err := root.OpenFile("durable-prefix", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			_, err = f.Write([]byte("one prior removal and parent fsync returned"))
			if err == nil {
				err = f.Sync()
			}
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if err = syncRoot(root); err != nil {
				return err
			}
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	})
	if err != nil {
		t.Fatal("same captured cleanup failed", err)
	}
}

func TestNativeSandboxCleanupSurvivesProcessCrash(t *testing.T) {
	p, directory, id, stamp := sandboxNative(t)
	for _, name := range []string{"one", "two", "three", "four"} {
		if err := os.WriteFile(filepath.Join(directory, id, "rw", name), []byte("owned"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("RUNNERD09_SANDBOX_STRESS") == "1" {
		sandboxStressWorkers(t, 32)
	}
	fixture := sandboxCrashFixture{Directory: directory, ID: id, Stamp: stamp}
	if os.Getenv("RUNNERD09_SANDBOX_STRESS_GUARDS") == "production-readonly" {
		fixture.Guard = &sandboxGuardSnapshot{}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		sandboxProductionStressGuard(t, ctx, p, directory, id, fixture.Guard)
		cancel()
	}
	raw, _ := json.Marshal(fixture)
	config := filepath.Join(directory, "fixture.json")
	root, err := hostfs.OpenState(directory)
	if err != nil {
		t.Fatal(err)
	}
	f, err := root.OpenFile("fixture.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		root.Close()
		t.Fatal(err)
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close(), syncRoot(root), root.Close())
	if err != nil {
		t.Fatal("original fixture ownership not durable", err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := func(phase string) *exec.Cmd {
		cmd := exec.Command(binary, "-test.run=^TestSandboxCleanupProcessChild$", "-test.timeout=70s")
		cmd.Env = append(os.Environ(), "RUNNERD09_SANDBOX_CHILD_FIXTURE="+config, "RUNNERD09_SANDBOX_CHILD_PHASE="+phase)
		return cmd
	}
	first := child("pause")
	if err = first.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Process.Kill() }()
	done := make(chan error, 1)
	go func() { done <- first.Wait() }()
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
wait:
	for {
		select {
		case err := <-done:
			t.Fatal("cleanup child exited before durable prefix", err)
		case <-deadline.C:
			t.Fatal("cleanup child did not publish durable prefix")
		case <-tick.C:
			if _, err = os.Stat(filepath.Join(directory, "durable-prefix")); err == nil {
				break wait
			}
		}
	}
	entries, err := os.ReadDir(filepath.Join(directory, id, "rw"))
	if err != nil || len(entries) != 4 {
		t.Fatal("first process did not durably remove exactly one file", len(entries), err)
	}
	if err = first.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("killed cleanup child did not exit")
	}
	second := child("complete")
	if raw, err = second.CombinedOutput(); err != nil {
		t.Fatalf("fresh process did not resume original captured identity: %v: %s", err, raw)
	}
	if _, err = os.Stat(filepath.Join(directory, id)); !os.IsNotExist(err) {
		t.Fatal("resumed cleanup left metadata", err)
	}
	t.Log("SIGKILL after durable prefix; fresh process completed same captured inode; synthetic native cleanup only")
}
