//go:build linux

package katalinux

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This acceptance case intentionally fails on the unfenced cleanup path. A
// reference found by an earlier procfs scan cannot cover acquisition at the
// subsequent real unlinkat boundary. Do not turn the observed violation into
// an expected-success assertion or replace the real removal with a test hook.
func TestNativeSandboxLateReferenceAtUnlink(t *testing.T) {
	control, _, controlID, controlStamp := sandboxNative(t)
	settleSandboxTest(t, func() error {
		return control.removeSandboxResidue(t.Context(), controlID, []SandboxDirectory{controlStamp}, func() error { return nil })
	})
	_, directory, id, stamp := sandboxNative(t)
	cc, err := exec.LookPath("cc")
	if err != nil {
		nativeUnavailable(t, "C compiler required for child-only late-reference probe")
	}
	probe := filepath.Join(t.TempDir(), "late-reference-probe")
	compile, cancelCompile := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancelCompile()
	if raw, err := exec.CommandContext(compile, cc, "-O2", "-Wall", "-Wextra", "-Werror", "testdata/late_reference_probe.c", "-o", probe).CombinedOutput(); err != nil {
		t.Fatalf("compile late-reference probe: %v: %s", err, raw)
	}
	fixture := sandboxCrashFixture{Directory: directory, ID: id, Stamp: stamp}
	raw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(directory, "late-reference-fixture.json")
	if err := os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	out, runErr := exec.CommandContext(ctx, probe, binary, config, filepath.Join(directory, id, "rw", "hosts")).CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("late-reference probe exceeded bounded child lifetime: %v: %s", ctx.Err(), out)
	}
	var result struct {
		Probe                            string `json:"probe"`
		AttemptedAtUnlink                bool   `json:"attemptedAtUnlink"`
		OpenedAtUnlink                   bool   `json:"openedAtUnlink"`
		OpenErrno                        int    `json:"openErrno"`
		UnlinkObserved                   bool   `json:"unlinkObserved"`
		UnlinkResult                     int64  `json:"unlinkResult"`
		UnlinkError                      bool   `json:"unlinkError"`
		SameHeldInodeAfter               bool   `json:"sameHeldInodeAfter"`
		TargetAbsent                     bool   `json:"targetAbsent"`
		TargetSameInodeAfter             bool   `json:"targetSameInodeAfter"`
		ChildExitCode                    int    `json:"childExitCode"`
		TraceError                       bool   `json:"traceError"`
		ReferenceSafetyViolationObserved bool   `json:"referenceSafetyViolationObserved"`
	}
	receipts := 0
	for line := range strings.SplitSeq(string(out), "\n") {
		if !strings.HasPrefix(line, `{"probe":`) {
			continue
		}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			t.Fatalf("invalid late-reference receipt: %v: %s", err, out)
		}
		receipts++
		t.Log(line)
	}
	if receipts != 1 || result.Probe != "late-opath-unlinkat-v1" || !result.AttemptedAtUnlink || !result.UnlinkObserved || result.TraceError {
		t.Fatalf("late acquisition coverage unavailable; missing trigger or trace failure: %v: %s", runErr, out)
	}
	if result.ReferenceSafetyViolationObserved || result.OpenedAtUnlink && (result.TargetAbsent || !result.TargetSameInodeAfter || result.ChildExitCode == 0 || !result.UnlinkError) {
		t.Fatalf("late O_PATH reference did not preserve inode and refuse cleanup; #328 acquisition fence required: %s", out)
	}
	if result.OpenedAtUnlink {
		if result.OpenErrno != 0 || !result.SameHeldInodeAfter || result.UnlinkResult >= 0 || result.ChildExitCode != 1 || runErr != nil || !strings.Contains(string(out), sandboxChildReferenceRejection) {
			t.Fatalf("incomplete held-reference preservation proof: %v: %s", runErr, out)
		}
	} else if (result.OpenErrno != int(unix.EACCES) && result.OpenErrno != int(unix.EPERM)) || result.ChildExitCode != 0 || !result.TargetAbsent || result.UnlinkError || result.UnlinkResult != 0 || runErr != nil {
		// The initial O_PATH preflight must succeed; denial at unlink alone is
		// useful only if cleanup then completes. Unrelated child failure cannot
		// turn missing acquisition coverage into a passing fence demonstration.
		t.Fatalf("incomplete acquisition-denial/completion proof: %v: %s", runErr, out)
	}
	if result.OpenedAtUnlink {
		info, err := os.Lstat(filepath.Join(directory, id, "rw", "hosts"))
		if err != nil || info == nil {
			t.Fatal("held target missing after probe", err)
		}
	} else if _, err := os.Lstat(filepath.Join(directory, id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("denied acquisition did not permit complete cleanup", err)
	}
}
