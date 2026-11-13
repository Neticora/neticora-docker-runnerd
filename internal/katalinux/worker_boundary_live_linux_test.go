//go:build linux && runnerd_kata

package katalinux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/workerboundary"
	"golang.org/x/sys/unix"
)

func TestRunnerd09LiveWorkerBoundary(t *testing.T) {
	if os.Getenv("RUNNERD09_LIVE_LAB") != "1" {
		nativeUnavailable(t, "explicit dedicated namespace boundary lab required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	p, _, plan, op, stamp := liveRetirementFixture(t, ctx)
	transient, err := os.MkdirTemp("/run", "nr9-boundary-")
	if err != nil {
		t.Fatal(err)
	}
	// Retained root-private fixture. No original resource index is changed.
	source := filepath.Join(transient, "keeper.c")
	if err = os.WriteFile(source, workerboundary.NativeSource, 0600); err != nil {
		t.Fatal(err)
	}
	keeper := filepath.Join(transient, "keeper")
	probe := filepath.Join(transient, "probe")
	for _, command := range [][]string{{"cc", "-Wall", "-Wextra", "-Werror", "-std=gnu11", source, "-o", keeper}, {"cc", "-Wall", "-Wextra", "-Werror", "-std=gnu11", "testdata/boundary_probe.c", "-o", probe}} {
		raw, e := exec.CommandContext(ctx, command[0], command[1:]...).CombinedOutput()
		if e != nil {
			t.Fatalf("compile: %v %s", e, raw)
		}
	}
	label := "neticora-native-boundary-" + plan.Name[4:24]
	profile := filepath.Join(transient, "apparmor")
	// Native ABI fixture only. This broad filesystem profile deliberately does
	// not qualify Kata's production write/IPC policy or a runtime integration.
	policy := fmt.Sprintf("profile %s flags=(attach_disconnected,mediate_deleted) {\n file,\n network,\n capability,\n mount,\n umount,\n signal,\n /** ix,\n deny capability mac_admin,\n deny capability mac_override,\n deny ptrace,\n}\n", label)
	if err = os.WriteFile(profile, []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}
	if raw, e := exec.CommandContext(ctx, "apparmor_parser", "-a", profile).CombinedOutput(); e != nil {
		t.Fatalf("enforcing profile load: %v %s", e, raw)
	}
	group, err := p.cgroupRecord(plan)
	if err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join("/sys/fs/cgroup", group.Path, "namespace-init")
	if err = os.Mkdir(leaf, 0755); err != nil {
		t.Fatal(err)
	}
	// Delegate a read-only handle to the actual ancestor PID namespace solely
	// for this negative control. This tests the syscall policy independently of
	// the profile's additional /proc ptrace/read denial.
	ancestor := filepath.Join(transient, "ancestor-pidns")
	if err = os.WriteFile(ancestor, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err = unix.Mount("/proc/self/ns/pid", ancestor, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := unix.Unmount(ancestor, 0); e != nil {
			t.Error(e)
		}
	})
	cg, err := os.Open(leaf)
	if err != nil {
		t.Fatal(err)
	}
	defer cg.Close()
	helperBytes, err := os.ReadFile(keeper)
	if err != nil {
		t.Fatal(err)
	}
	helperDigest := sha256.Sum256(helperBytes)
	policyDigest := sha256.Sum256([]byte(policy))
	binding := workerboundary.Binding{InstallationID: "native-installation", TenantID: "native-tenant", HostID: "native-host", SessionEpoch: "1", Endpoint: "native-endpoint", ExecutionID: plan.Name, Generation: "1", SpecHash: plan.Config.Labels["com.neticora.runnerd.spec"], Profile: p.ID, Name: plan.Name}
	registry := workerboundary.Registry{Directory: p.EvidenceDirectory}
	domain, err := registry.Create(ctx, binding, op, keeper, hex.EncodeToString(helperDigest[:]), hex.EncodeToString(policyDigest[:]), filepath.Join(transient, "d.sock"), label, int(cg.Fd()))
	var id workerboundary.Identity
	if domain.Identity != nil {
		id = *domain.Identity
	}

	if err != nil {
		t.Fatalf("namespace start (retain original): %+v %v", id, err)
	}
	retired := false
	t.Cleanup(func() {
		if !retired {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cleanupCancel()
			if e := id.Retire(cleanupCtx); e != nil {
				t.Errorf("retain boundary fixture for inspection: %v", e)
				return
			}
		}
		if e := id.CheckRetired(); e != nil {
			t.Error(e)
			return
		}
		if raw, e := exec.Command("apparmor_parser", "-R", profile).CombinedOutput(); e != nil {
			t.Errorf("owned profile removal: %v %s", e, raw)
		}
	})
	raw, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(p.EvidenceDirectory, plan.Name+".native-boundary.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(filepath.Join(transient, "worker.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	in, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	stdio := [3]*os.File{in, out, out}
	outside := filepath.Join(transient, "outside.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: outside, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan error, 1)
	go func() {
		c, e := listener.AcceptUnix()
		if e != nil {
			received <- e
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		data := make([]byte, 64)
		control := make([]byte, 256)
		n, oob, flags, _, e := c.ReadMsgUnix(data, control)
		if e == nil && (oob != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || string(data[:n]) != "plain-byte-stream") {
			e = fmt.Errorf("unexpected receiver data: bytes=%d ancillary=%d flags=%x payload=%q", n, oob, flags, data[:n])
		}
		received <- e
	}()
	if err = id.Run(ctx, []string{probe, "transfer", outside, filepath.Join(stamp.Root, strings.Repeat("a", 64))}, stdio); err != nil {
		t.Fatal(err)
	}
	if err = <-received; err != nil {
		t.Fatal(err)
	}
	// Even with an actual ancestor handle, inferred/explicit PID setns must be
	// denied by syscall policy; no host namespace is entered.
	if err = id.Run(ctx, []string{probe, "escape", ancestor}, stdio); err != nil {
		t.Fatal(err)
	}
	if err = id.Run(ctx, []string{probe, "keeper-control", id.Socket}, stdio); err != nil {
		t.Fatal(err)
	}
	if id.Check() != nil {
		t.Fatal("inner-root request changed original namespace-init ownership")
	}
	report := filepath.Join(transient, "holder")
	if err = id.Run(ctx, []string{probe, "hold", filepath.Join(stamp.Root, strings.Repeat("a", 64)), report}, stdio); err != nil {
		t.Fatal(err)
	}
	var holder string
	for i := 0; i < 100; i++ {
		b, e := os.ReadFile(report)
		if e == nil {
			holder = string(b)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	parts := strings.Fields(holder)
	if len(parts) != 3 {
		t.Fatal("holder identity missing")
	}
	namespacePID, err := strconv.Atoi(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	if parts[1] != strconv.FormatUint(stamp.Device, 10) || parts[2] != strconv.FormatUint(stamp.Inode, 10) {
		t.Fatal("wrong original inode")
	}
	processes, err := os.ReadFile(filepath.Join(leaf, "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	hostPID := 0
	for _, pid := range strings.Fields(string(processes)) {
		b, e := os.ReadFile("/proc/" + pid + "/status")
		if e != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "NSpid:") {
				f := strings.Fields(line)
				if len(f) == 3 && f[2] == strconv.Itoa(namespacePID) {
					hostPID, _ = strconv.Atoi(pid)
				}
			}
		}
	}
	if hostPID < 2 {
		t.Fatal("surviving fork was not visible in original cgroup")
	}
	processFD, err := unix.PidfdOpen(hostPID, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(processFD)
	// Move only the original verified namespace init and reference holder into
	// a DIFFERENT owned test slice. The complete original hierarchy must become
	// empty while the reference remains alive; a sibling leaf is not this test.
	other, _, otherPlan, _, _ := liveRetirementFixture(t, ctx)
	otherGroup, err := other.cgroupRecord(otherPlan)
	if err != nil {
		t.Fatal(err)
	}
	migrated := filepath.Join("/sys/fs/cgroup", otherGroup.Path, "migration-negative")
	if err = os.Mkdir(migrated, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(migrated, "cgroup.procs"), []byte(strconv.Itoa(hostPID)), 0600); err != nil {
		t.Fatal(err)
	}
	if id.Check() != nil {
		t.Fatal("original init identity changed before controlled migration")
	}
	if err = os.WriteFile(filepath.Join(migrated, "cgroup.procs"), []byte(strconv.Itoa(id.PID)), 0600); err != nil {
		t.Fatal(err)
	}
	settleSandboxTest(t, func() error {
		_, populated, e := inspectCgroup(group)
		if e != nil || populated {
			return ErrQualification
		}
		return nil
	})
	if id.Check() != nil || id.CheckRetired() == nil {
		t.Fatal("migrated live worker escaped lifetime obligation")
	}
	if actual, e := sandboxStamp(p.Manifest.Storage.Runtime.Root, stamp.Root, strings.Repeat("a", 64)); e != nil || actual != stamp {
		t.Fatal("metadata changed before domain retirement", e)
	}
	removeOperation := strings.Repeat("4", 64)
	original := domain
	if _, err = registry.BeginRetirement(binding, removeOperation); err != nil {
		t.Fatal(err)
	}
	if err = id.Retire(ctx); err != nil {
		t.Fatal(err)
	}
	// Reopen the protected record after the kernel effect but before completion,
	// exactly the durable interval a broker SIGKILL must preserve.
	reopened := workerboundary.Registry{Directory: p.EvidenceDirectory}
	held, err := reopened.Load(binding)
	if err != nil || held.Phase != "RETIRING" || !held.SameOriginal(original) {
		t.Fatal("interrupted namespace retirement lost original ownership", err)
	}
	finished, err := reopened.Retire(ctx, binding, removeOperation)
	if err != nil || finished.Phase != "RETIRED" || !finished.SameOriginal(original) {
		t.Fatal("recovery replaced original domain", err)
	}
	if _, err = reopened.Retire(ctx, binding, strings.Repeat("5", 64)); err == nil {
		t.Fatal("replacement removal authority accepted")
	}
	if _, err = reopened.CheckRetired(binding, removeOperation); err != nil {
		t.Fatal(err)
	}
	if _, err = reopened.Create(ctx, binding, op, keeper, hex.EncodeToString(helperDigest[:]), hex.EncodeToString(policyDigest[:]), id.Socket, label, int(cg.Fd())); err == nil {
		t.Fatal("retired domain was re-created")
	}
	retired = true
	if err = id.CheckRetired(); err != nil {
		t.Fatal(err)
	}
	polls := []unix.PollFd{{Fd: int32(processFD), Events: unix.POLLIN}}
	if n, e := unix.Poll(polls, 0); e != nil || n != 1 || polls[0].Revents&unix.POLLIN == 0 {
		t.Fatal("namespace retirement missed migrated reference holder", e)
	}
	if id.Run(ctx, []string{probe, "hold", stamp.Root, report}, stdio) == nil {
		t.Fatal("retired namespace admitted replacement worker")
	}
	bootChanged := id
	bootChanged.Boot = "unsupported-boot"
	if bootChanged.CheckRetired() == nil {
		t.Fatal("boot change discharged original boundary")
	}
	t.Logf("original namespace init %d; surviving reference holder %d retired despite cgroup migration; outbound SCM_RIGHTS/sendmmsg/io_uring and PID setns denied; inner-root control denied; original metadata retained; no block/disposal/capacity authority", id.PID, hostPID)
}
