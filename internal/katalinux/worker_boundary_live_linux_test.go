//go:build linux && runnerd_kata

package katalinux

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/workerboundary"
	"golang.org/x/sys/unix"
)

var workerBoundaryCandidateCommit string // Set from committed HEAD at build.

//go:embed testdata/boundary_probe.c
var workerBoundaryProbeSource []byte

// This nonprivileged stamp is checked before staging any native effects. Both
// C sources are inside the executable; a failed build cannot reuse an old probe.
func TestRunnerd09BoundaryBuildStamp(t *testing.T) {
	helper := sha256.Sum256(workerboundary.NativeSource)
	probe := sha256.Sum256(workerBoundaryProbeSource)
	fmt.Printf("RUNNERD09_BOUNDARY_BUILD %s %x %x\n", workerBoundaryCandidateCommit, helper, probe)
}

type workerBoundaryCrashRequest struct {
	Directory string                 `json:"directory"`
	Binding   workerboundary.Binding `json:"binding"`
	Operation string                 `json:"operation"`
	Ready     string                 `json:"ready"`
}

// Native subprocess only: persist the original retirement intent and wait for
// the parent to SIGKILL this exact process. No namespace signal/disposal occurs.
func TestRunnerd09WorkerBoundaryCrashHelper(t *testing.T) {
	path := os.Getenv("RUNNERD09_BOUNDARY_CRASH_REQUEST")
	if path == "" {
		t.Skip("parent-controlled native crash helper")
	}
	if os.Geteuid() != 0 || os.Getenv("RUNNERD09_LIVE_LAB") != "1" || workerBoundaryCandidateCommit != os.Getenv("RUNNERD09_EXPECTED_CANDIDATE") {
		t.Fatal("explicit committed native helper required")
	}
	raw, err := hostfs.ReadPrivate(path, 32768)
	var request workerBoundaryCrashRequest
	if err != nil || json.Unmarshal(raw, &request) != nil {
		t.Fatal("protected helper request unavailable", err)
	}
	record, err := (workerboundary.Registry{Directory: request.Directory}).BeginRetirement(request.Binding, request.Operation)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(request.Ready, []byte(record.Owner), 0600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Second)
	}
}

func TestRunnerd09LiveWorkerBoundary(t *testing.T) {
	if os.Getenv("RUNNERD09_LIVE_LAB") != "1" {
		nativeUnavailable(t, "explicit dedicated namespace boundary lab required")
	}
	if len(workerBoundaryCandidateCommit) != 40 || workerBoundaryCandidateCommit != os.Getenv("RUNNERD09_EXPECTED_CANDIDATE") {
		t.Fatal("native executable candidate differs from expected committed source")
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
	probeSource := filepath.Join(transient, "probe.c")
	if err = os.WriteFile(probeSource, workerBoundaryProbeSource, 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{{"cc", "-Wall", "-Wextra", "-Werror", "-std=gnu11", source, "-o", keeper}, {"cc", "-Wall", "-Wextra", "-Werror", "-std=gnu11", probeSource, "-o", probe}} {
		raw, e := exec.CommandContext(ctx, command[0], command[1:]...).CombinedOutput()
		if e != nil {
			t.Fatalf("compile: %v %s", e, raw)
		}
	}
	label := "neticora-native-boundary-" + plan.Name[4:24]
	profile := filepath.Join(transient, "apparmor")
	// Native ABI fixture only. This broad filesystem profile deliberately does
	// not qualify Kata's production write/IPC policy or a runtime integration.
	policy := fmt.Sprintf("profile %s flags=(attach_disconnected,mediate_deleted) {\n file,\n network,\n capability,\n mount,\n umount,\n signal,\n /** ix,\n deny capability mac_admin,\n deny capability mac_override,\n ptrace (readby, tracedby) peer=unconfined,\n ptrace (read) peer=%s,\n}\n", label, label)
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
	if err = id.Run(ctx, []string{probe, "internal-transfer", filepath.Join(stamp.Root, strings.Repeat("a", 64))}, stdio); err != nil {
		t.Fatal("verified internal FD transfer or sealed relay negative control failed", err)
	}
	if err = id.Run(ctx, []string{probe, "privileges", "check"}, stdio); err != nil {
		t.Fatal(err)
	}
	// A privileged API/socket cannot be smuggled into standard input before the
	// worker filter starts. Known ordinary stdio remains a positive control.
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	unsafeInput := os.NewFile(uintptr(pair[0]), "fixture-privileged-socket")
	defer unsafeInput.Close()
	defer unix.Close(pair[1])
	if err = id.Run(ctx, []string{probe, "privileges", "check"}, [3]*os.File{unsafeInput, out, out}); err == nil {
		t.Fatal("socket in stdio bypassed worker entry controls")
	}
	outside := filepath.Join(transient, "outside.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: outside, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
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
		}
	}()
	if err = id.Run(ctx, []string{probe, "transfer", outside, filepath.Join(stamp.Root, strings.Repeat("a", 64))}, stdio); err != nil {
		t.Fatal(err)
	}
	if err = <-received; err != nil {
		t.Fatal(err)
	}
	if err = id.Run(ctx, []string{probe, "race-transfer", outside, filepath.Join(stamp.Root, strings.Repeat("a", 64))}, stdio); err != nil {
		t.Fatal("concurrent socket substitution bypassed or broke mediation", err)
	}
	if err = <-received; err != nil {
		t.Fatal("outward descriptor during concurrent socket replacement", err)
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
	// Move the original init, reference holder and all trusted transfer guardians
	// into a DIFFERENT owned test slice. Freeze both owned leaves before reading
	// their task IDs so no fixture task can exit/fork during numeric migration.
	// The original hierarchy becomes empty while all references remain alive.
	other, _, otherPlan, _, _ := liveRetirementFixture(t, ctx)
	otherGroup, err := other.cgroupRecord(otherPlan)
	if err != nil {
		t.Fatal(err)
	}
	migrated := filepath.Join("/sys/fs/cgroup", otherGroup.Path, "migration-negative")
	if err = os.Mkdir(migrated, 0755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{leaf, migrated} {
		if err = os.WriteFile(filepath.Join(path, "cgroup.freeze"), []byte("1"), 0600); err != nil {
			t.Fatal(err)
		}
		defer os.WriteFile(filepath.Join(path, "cgroup.freeze"), []byte("0"), 0600)
		settleSandboxTest(t, func() error {
			b, e := os.ReadFile(filepath.Join(path, "cgroup.events"))
			if e != nil || !strings.Contains(string(b), "frozen 1") {
				return ErrQualification
			}
			return nil
		})
	}
	processes, err = os.ReadFile(filepath.Join(leaf, "cgroup.procs"))
	if err != nil || id.Check() != nil {
		t.Fatal("original namespace unavailable before frozen fixture migration", err)
	}
	for _, pid := range strings.Fields(string(processes)) {
		info, e := os.Stat(filepath.Join("/proc", pid, "ns/pid"))
		if e != nil {
			t.Fatal(e)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Ino != id.PIDNamespaceInode || uint64(stat.Dev) != id.PIDNamespaceDevice {
			t.Fatal("unowned task in native migration fixture")
		}
		if err = os.WriteFile(filepath.Join(migrated, "cgroup.procs"), []byte(pid), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{leaf, migrated} {
		if err = os.WriteFile(filepath.Join(path, "cgroup.freeze"), []byte("0"), 0600); err != nil {
			t.Fatal(err)
		}
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
	if profileFile := os.Getenv("RUNNERD09_KATA_COMPONENT_PROFILE"); profileFile != "" {
		raw, e := hostfs.ReadPrivate(profileFile, 262144)
		var artifact struct {
			Manifest Manifest `json:"manifest"`
		}
		if e != nil || json.Unmarshal(raw, &artifact) != nil {
			t.Fatal("protected historical Kata tuple unavailable", e)
		}
		m := artifact.Manifest
		if digestFile(m.DockerConfig, m.Files[m.DockerConfig]) != nil {
			t.Fatal("dedicated daemon configuration differs from pinned tuple")
		}
		configBytes, e := os.ReadFile(m.DockerConfig)
		var daemonConfig struct {
			ExecRoot   string `json:"exec-root"`
			Containerd string `json:"containerd"`
		}
		if e != nil || json.Unmarshal(configBytes, &daemonConfig) != nil {
			t.Fatal("protected dedicated daemon addresses unavailable", e)
		}
		address := daemonConfig.Containerd
		if address == "" && filepath.IsAbs(daemonConfig.ExecRoot) {
			address = filepath.Join(daemonConfig.ExecRoot, "containerd/containerd.sock")
		}
		addressInfo, e := os.Stat(address)
		if e != nil || !filepath.IsAbs(address) || addressInfo.Mode()&os.ModeSocket == 0 {
			t.Fatal("dedicated containerd socket unavailable", e)
		}
		publisher := os.Getenv("RUNNERD09_CONTAINERD_PUBLISH_BINARY")
		if !filepath.IsAbs(publisher) || digestFile(publisher, os.Getenv("RUNNERD09_CONTAINERD_PUBLISH_SHA256")) != nil {
			t.Fatal("independently pinned dedicated containerd publisher unavailable")
		}
		for _, binary := range []string{m.ShimBinary, m.QEMUBinary, "/opt/kata/libexec/virtiofsd"} {
			if digestFile(binary, m.Files[binary]) != nil {
				t.Fatal("actual Kata binary differs from pinned historical tuple")
			}
			if e = id.Run(ctx, []string{binary, "--version"}, stdio); e != nil {
				t.Fatal("filtered Kata binary version ABI failed", binary, e)
			}
		}
		// Shim start creates only its task-service endpoint. No TaskCreate RPC,
		// Docker lifecycle request, guest bootstrap, block allocation or VM is used.
		// A fresh containerd namespace/SID cannot adopt any original execution.
		bundle := filepath.Join(transient, "abi-bundle")
		if e = os.Mkdir(bundle, 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.Mkdir(filepath.Join(bundle, "rootfs"), 0700); e != nil {
			t.Fatal(e)
		}
		oci := `{"ociVersion":"1.0.2","process":{"terminal":false,"args":["/bin/true"],"cwd":"/"},"root":{"path":"rootfs"},"linux":{"namespaces":[]}}`
		if e = os.WriteFile(filepath.Join(bundle, "config.json"), []byte(oci), 0600); e != nil {
			t.Fatal(e)
		}
		sidHash := sha256.Sum256([]byte(plan.Name + " native shim ABI"))
		sid := hex.EncodeToString(sidHash[:])
		args := []string{"/usr/bin/env", "-C", bundle, "KATA_CONF_FILE=" + m.RuntimeConfig, m.ShimBinary, "-namespace", "neticora-f5a2-native", "-address", address, "-publish-binary", publisher, "-id", sid, "start"}
		if e = id.Run(ctx, args, stdio); e != nil {
			t.Fatal("filtered real shim start ABI failed; no runtime qualification", e)
		}
		foundShim := false
		entries, e := os.ReadDir("/proc")
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			if _, e = strconv.Atoi(entry.Name()); e != nil {
				continue
			}
			path := filepath.Join("/proc", entry.Name())
			args, e := os.ReadFile(filepath.Join(path, "cmdline"))
			if e != nil || !strings.Contains(string(args), sid) {
				continue
			}
			exe, e := os.Readlink(filepath.Join(path, "exe"))
			if e != nil || exe != m.ShimBinary {
				continue
			}
			info, e := os.Stat(filepath.Join(path, "ns/pid"))
			if e != nil {
				t.Fatal(e)
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Ino != id.PIDNamespaceInode || uint64(stat.Dev) != id.PIDNamespaceDevice {
				t.Fatal("actual shim escaped original PID lifetime namespace")
			}
			foundShim = true
		}
		if !foundShim {
			t.Fatal("real shim start returned without original namespace worker")
		}
		t.Log("Pinned real shim/QEMU/virtiofsd version ABI and real shim start passed inside original namespace; no TaskCreate, Docker job, VM or storage qualification")
	}
	if actual, e := sandboxStamp(p.Manifest.Storage.Runtime.Root, stamp.Root, strings.Repeat("a", 64)); e != nil || actual != stamp {
		t.Fatal("metadata changed before domain retirement", e)
	}
	removeOperation := strings.Repeat("4", 64)
	original := domain
	// Start bounded acquisition concurrently with an interrupted retirement.
	// Every new helper inherits the namespace/filter; none is reconstructed from
	// a post-hoc process scan as disposal authority.
	acquiring := filepath.Join(transient, "acquiring")
	if err = id.Run(ctx, []string{probe, "acquire-loop", filepath.Join(stamp.Root, strings.Repeat("a", 64)), acquiring}, stdio); err != nil {
		t.Fatal(err)
	}
	settleSandboxTest(t, func() error { _, e := os.Stat(acquiring); return e })
	crashRequest := workerBoundaryCrashRequest{Directory: registry.Directory, Binding: binding, Operation: removeOperation, Ready: filepath.Join(transient, "retirement-ready")}
	requestBytes, err := json.Marshal(crashRequest)
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(transient, "crash-request.json")
	if err = os.WriteFile(requestPath, requestBytes, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	owner := exec.CommandContext(ctx, executable, "-test.run", "^TestRunnerd09WorkerBoundaryCrashHelper$", "-test.timeout=60s")
	owner.Env = append(os.Environ(), "RUNNERD09_BOUNDARY_CRASH_REQUEST="+requestPath)
	owner.Stdout, owner.Stderr = out, out
	if err = owner.Start(); err != nil {
		t.Fatal(err)
	}
	defer owner.Process.Kill()
	settleSandboxTest(t, func() error {
		b, e := os.ReadFile(crashRequest.Ready)
		if e != nil || string(b) != original.Owner {
			return workerboundary.ErrBoundary
		}
		return nil
	})
	if err = owner.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = owner.Wait(); err == nil || !owner.ProcessState.Sys().(syscall.WaitStatus).Signaled() || owner.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatal("retirement owner did not crash by SIGKILL", err)
	}
	preserved, err := (workerboundary.Registry{Directory: registry.Directory}).Load(binding)
	if err != nil || !preserved.SameOriginal(original) || preserved.Phase != "RETIRING" || id.CheckRetired() == nil {
		t.Fatal("owner crash lost original live retirement obligation", err)
	}
	t.Log("SIGKILL after durable RETIRING preserved original owner and live acquisition obligation; no disposal or capacity release")
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
	if err = out.Sync(); err != nil {
		t.Fatal(err)
	}
	workerLog, err := os.ReadFile(out.Name())
	if err != nil || len(workerLog) > 65536 {
		t.Fatal("bounded native component diagnostics unavailable", err)
	}
	t.Logf("native component diagnostics (no provider/authorization credentials):\n%s", workerLog)
	bootChanged := id
	bootChanged.Boot = "unsupported-boot"
	if bootChanged.CheckRetired() == nil {
		t.Fatal("boot change discharged original boundary")
	}
	t.Logf("original namespace init %d; surviving reference holder %d retired despite cgroup migration; outbound SCM_RIGHTS/sendmmsg/io_uring and PID setns denied; inner-root control denied; original metadata retained; no block/disposal/capacity authority", id.PID, hostPID)
}
