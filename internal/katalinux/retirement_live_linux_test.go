//go:build linux && runnerd_kata

package katalinux

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/moby/moby/api/types/container"
)

// This is the bounded replacement gate. It does not change or suppress the
// unrestricted-root late-unlink diagnostic. No original VM allocation is touched.
func TestRunnerd09LiveRetirementAcquisitionDomain(t *testing.T) {
	if os.Getenv("RUNNERD09_LIVE_LAB") != "1" {
		nativeUnavailable(t, "explicit disposable root/systemd retirement lab required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	for _, mode := range []string{"empty", "fd", "opath", "dir", "cwd", "root", "mmap", "namespace-hidden-bind"} {
		t.Run(mode, func(t *testing.T) {
			p, id, plan, op, stamp := liveRetirementFixture(t, ctx)
			if err := p.BeginRetirement(id, plan, op); err != nil {
				t.Fatal(err)
			}
			var retireWorker func()
			if mode != "empty" {
				target := filepath.Join(stamp.Root, id)
				if mode == "fd" || mode == "opath" || mode == "mmap" {
					target = filepath.Join(target, "rw", "hosts")
				}
				retireWorker = liveRetirementWorker(t, ctx, p, plan, mode, target)
				_, err := p.FenceRetirement(ctx, id, plan, op, func() error { return nil })
				if err == nil {
					t.Fatal("surviving worker passed fence")
				}
				r, e := p.retirementRecord(plan)
				if e != nil || r.Phase != "INTENT" || !r.Quarantined || r.FencedAt != "" {
					t.Fatal("worker did not preserve owned quarantine", r, e)
				}
				if actual, e := sandboxStamp(p.Manifest.Storage.Runtime.Root, stamp.Root, id); e != nil || actual != stamp {
					t.Fatal("uncertain resource changed", e)
				}
				if p.RequireAcquisition(plan) == nil {
					t.Fatal("quarantine granted reuse")
				}
				retireWorker()
			}
			var r RetirementRecord
			settleSandboxTest(t, func() error {
				var err error
				r, err = p.FenceRetirement(ctx, id, plan, op, func() error { return nil })
				return err
			})
			if r.Phase != "FENCED" || r.Quarantined || r.Cgroup.Inode == 0 {
				t.Fatal(r)
			}
			// Same uid/groups/capability boundary as the installed nonroot controller.
			// Repeated attempts overlap actual reclamation; successful acquisition is fatal.
			denied := liveDeniedAcquisitions(t, filepath.Join(stamp.Root, id))
			r.Phase = "RECLAIMING"
			if err := p.persistRetirement(r); err != nil {
				t.Fatal(err)
			}
			f := &retirementFence{profile: p, plan: plan, record: r}
			fenced := context.WithValue(ctx, retirementFenceKey{}, f)
			if err := p.removeSandboxResidue(fenced, id, []SandboxDirectory{stamp}, func() error { return f.verify(ctx) }); err != nil {
				t.Fatal(err)
			}
			denied()
			if _, err := os.Stat(filepath.Join(stamp.Root, id)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("original metadata not reclaimed", err)
			}
			if p.RequireAcquisition(plan) == nil {
				t.Fatal("tombstone allowed acquisition after unlink")
			}
			if err := p.prepareHostCgroup(ctx, plan); err != nil {
				t.Fatal("kernel identity unexpectedly changed", err)
			}
			t.Log("Acquisition-only fixture retains frozen empty owned slice; no block allocation or disposal certificate exists")
			t.Log("original identity retained; hierarchical worker quarantine, positive frozen-empty fence and nonroot acquisition denial verified")
		})
	}
}

func liveRetirementFixture(t *testing.T, ctx context.Context) (*Profile, string, dockerengine.Plan, string, SandboxDirectory) {
	t.Helper()
	fixture, err := os.MkdirTemp("", "runnerd09-retirement-")
	if err != nil {
		t.Fatal(err)
	}
	anchor := filepath.Join(fixture, "metadata")
	id := strings.Repeat("a", 64)
	if err = os.MkdirAll(filepath.Join(anchor, id, "rw"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(anchor, id, "rw", "hosts"), make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	stamp, err := sandboxStamp(anchor, anchor, id)
	if err != nil {
		t.Fatal(err)
	}
	p := &Profile{}
	t.Log("retained retirement fixture:", fixture)
	m := multiBlockFixture()
	m.Qualified = false
	m.RetirementPolicy = RetirementPolicy
	m.SandboxRoots = []string{anchor}
	m.Storage.Runtime.Root = anchor
	m.Storage.Runtime.Device = stamp.Device
	m.HostCgroup.SystemctlBinary = "/usr/bin/systemctl"
	m.HostCgroup.BusctlBinary = "/usr/bin/busctl"
	for _, binary := range []string{m.HostCgroup.SystemctlBinary, m.HostCgroup.BusctlBinary} {
		raw, err := os.ReadFile(binary)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(raw)
		m.Files[binary] = hex.EncodeToString(h[:])
	}
	p.Manifest = m
	p.ID = "docker-kata-rs-qemu-v3-" + strings.Repeat("1", 64)
	p.brokerOwned = true
	p.EvidenceDirectory = filepath.Join(fixture, "evidence")
	if err := os.Mkdir(p.EvidenceDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(t.Name() + " " + p.EvidenceDirectory))
	name := "nrd-" + hex.EncodeToString(h[:])
	plan := dockerengine.Plan{Name: name, Config: &container.Config{Labels: map[string]string{dockerengine.LabelPrefix + "spec": strings.Repeat("2", 64), dockerengine.LabelPrefix + "generation": "1"}}, HostConfig: &container.HostConfig{Resources: container.Resources{CgroupParent: hostCgroupUnit(name)}}}
	if err := p.prepareHostCgroup(ctx, plan); err != nil {
		t.Fatal(err)
	}
	group, err := p.cgroupRecord(plan)
	if err != nil {
		t.Fatal(err)
	}
	original := Evidence{Version: "runnerd09-physical-v1", Profile: p.ID, Container: id, SpecHash: plan.Config.Labels[dockerengine.LabelPrefix+"spec"], Generation: "1", Prepared: true, Cgroup: &group, Sandboxes: []SandboxDirectory{stamp}}
	root, err := hostfs.OpenState(p.EvidenceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	err = persist(root, plan.Name+".json", original)
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	return p, id, plan, strings.Repeat("3", 64), stamp
}
func liveRetirementWorker(t *testing.T, ctx context.Context, p *Profile, plan dockerengine.Plan, mode, target string) func() {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "worker")
	if raw, err := exec.Command("cc", "-Wall", "-Wextra", "-Werror", "-pthread", "testdata/surviving_worker.c", "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v %s", err, raw)
	}
	unit := "neticora-retirement-worker-" + plan.Name[4:20] + ".service"
	cmd := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--pipe", "--wait", "--collect", "--service-type=exec", "--property=ExitType=cgroup", "--slice="+hostCgroupUnit(plan.Name), "--unit="+unit, "--", binary, mode, target)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(out)
		if scanner.Scan() {
			ready <- scanner.Text()
		} else {
			ready <- ""
		}
	}()
	select {
	case line := <-ready:
		var tid int
		if _, err = fmt.Sscanf(line, "READY %d", &tid); err != nil {
			t.Fatalf("worker readiness %q %s", line, stderr.String())
		}
		// The leader is gone while the permitted reference-holding thread survives.
		stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(tid), "cgroup"))
		if err != nil || !strings.Contains(string(stat), hostCgroupPath(plan.Name)+"/") {
			t.Fatal("worker escaped original reference domain", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("worker readiness deadline")
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		if raw, err := exec.Command("/usr/bin/systemctl", "kill", "--signal=KILL", "--kill-whom=all", "--", unit).CombinedOutput(); err != nil {
			t.Errorf("fixture worker kill: %v %s", err, raw)
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("fixture worker remained alive")
		}
	}
	t.Cleanup(stop)
	return stop
}
func liveDeniedAcquisitions(t *testing.T, target string) func() {
	t.Helper()
	// Python is only a qualification probe, never a product lifecycle helper.
	script := `import os,time
assert os.geteuid()==10003 and os.getegid()==10003 and os.getgroups()==[]
assert int(next(x.split()[1] for x in open('/proc/self/status') if x.startswith('CapEff:')),16)==0
print('READY',flush=True)
for _ in range(500):
 try:
  fd=os.open(os.sys.argv[1],os.O_PATH);os.close(fd);raise RuntimeError('unauthorized acquisition')
 except OSError as e:
  assert e.errno==13,e
 time.sleep(.001)
print('DENIED',flush=True)
`
	cmd := exec.Command("/usr/bin/setpriv", "--reuid=10003", "--regid=10003", "--clear-groups", "--bounding-set=-all", "--no-new-privs", "/usr/bin/python3", "-c", script, target)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(out)
	if !scanner.Scan() || scanner.Text() != "READY" {
		t.Fatal("unprivileged probe not ready")
	}
	return func() {
		if !scanner.Scan() || scanner.Text() != "DENIED" {
			t.Error("unprivileged acquisition did not remain denied")
		}
		if err := cmd.Wait(); err != nil {
			t.Error(err)
		}
	}
}

func TestRunnerd09LiveRetirementCrashRecovery(t *testing.T) {
	if os.Getenv("RUNNERD09_LIVE_LAB") != "1" {
		nativeUnavailable(t, "explicit disposable root/systemd retirement lab required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	ctx := t.Context()
	for _, phase := range []string{"INTENT", "FENCED", "RECLAIMING"} {
		t.Run(phase, func(t *testing.T) {
			p, id, plan, op, stamp := liveRetirementFixture(t, ctx)
			fixture := struct {
				Profile   *Profile
				ID        string
				Plan      dockerengine.Plan
				Operation string
				Phase     string
			}{p, id, plan, op, phase}
			file := filepath.Join(p.EvidenceDirectory, "crash-fixture.json")
			raw, err := json.Marshal(fixture)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(binary, "-test.run=^TestRunnerd09LiveRetirementCrashChild$", "-test.v")
			cmd.Env = append(os.Environ(), "RUNNERD09_RETIREMENT_CRASH_FIXTURE="+file)
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || !exit.ProcessState.Sys().(syscall.WaitStatus).Signaled() || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("crash checkpoint missing: %v %s", err, output)
			}
			original, e := p.retirementRecord(plan)
			if e != nil || original.Phase != phase || original.OperationID != op {
				t.Fatal("durable checkpoint lost", original, e)
			}
			if actual, e := sandboxStamp(p.Manifest.Storage.Runtime.Root, stamp.Root, id); e != nil || actual != stamp {
				t.Fatal("crash replaced original resource", e)
			}
			resumed, e := p.FenceRetirement(ctx, id, plan, op, func() error { return nil })
			if e != nil || resumed.Cgroup != original.Cgroup || resumed.OperationID != op {
				t.Fatal("same-operation recovery failed", e)
			}
			resumed.Phase = "RECLAIMING"
			if err = p.persistRetirement(resumed); err != nil {
				t.Fatal(err)
			}
			f := &retirementFence{profile: p, plan: plan, record: resumed}
			if err = p.removeSandboxResidue(context.WithValue(ctx, retirementFenceKey{}, f), id, []SandboxDirectory{stamp}, func() error { return f.verify(ctx) }); err != nil {
				t.Fatal(err)
			}
			if p.RequireAcquisition(plan) == nil {
				t.Fatal("crash reopened acquisition")
			}
			t.Log("SIGKILL retained exact retirement phase, cgroup owner, metadata inode and original remove authority")
		})
	}
}
func TestRunnerd09LiveRetirementCrashChild(t *testing.T) {
	path := os.Getenv("RUNNERD09_RETIREMENT_CRASH_FIXTURE")
	if path == "" {
		t.Skip("subprocess only")
	}
	var fixture struct {
		Profile   *Profile
		ID        string
		Plan      dockerengine.Plan
		Operation string
		Phase     string
	}
	raw, err := hostfs.ReadPrivate(path, 32768)
	if err != nil || json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("protected crash fixture required", err)
	}
	p := fixture.Profile
	p.brokerOwned = true
	if err = p.BeginRetirement(fixture.ID, fixture.Plan, fixture.Operation); err != nil {
		t.Fatal(err)
	}
	if fixture.Phase != "INTENT" {
		r, err := p.FenceRetirement(t.Context(), fixture.ID, fixture.Plan, fixture.Operation, func() error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		if fixture.Phase == "RECLAIMING" {
			r.Phase = "RECLAIMING"
			if err = p.persistRetirement(r); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	t.Fatal("SIGKILL returned")
}
