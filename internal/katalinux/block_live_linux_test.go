//go:build linux && runnerd_kata

package katalinux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

// This opt-in test drives real production allocation/capture/disposal code on
// the explicitly prepared disposable VM. The descriptor stays UNQUALIFIED: no
// authority, platform host, provider token or admission setting is involved.
func TestRunnerd09LiveBlockLifecycle(t *testing.T) {
	if os.Getenv("RUNNERD09_LIVE_LAB") != "1" {
		t.Skip("explicit prepared disposable Kata lab required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root lab required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal("lab marker required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	base := "/var/lib/neticora-runnerd09-lab"
	for _, dir := range []string{base, base + "/evidence", base + "/journal", "/run/neticora-runnerd09-lab", "/run/neticora-runnerd09-lab/bootstrap", "/run/neticora-runnerd09-lab/bootstrap-health"} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	attempt := os.Getenv("RUNNERD09_LAB_ATTEMPT")
	if !regexp.MustCompile(`^[a-zA-Z0-9-]{1,48}$`).MatchString(attempt) {
		t.Fatal("explicit unique RUNNERD09_LAB_ATTEMPT required")
	}
	fault := os.Getenv("RUNNERD09_LAB_FAULT")
	if fault != "" && fault != "held-mmap" && fault != "interrupted-unlink" && fault != "guest-kill" {
		t.Fatal("unsupported bounded lab fault")
	}
	ledger := base + "/block-lifecycle-" + attempt + ".json"
	if _, err := os.Stat(ledger); !os.IsNotExist(err) {
		t.Fatal("prior probe requires explicit reconciliation; refusing duplicate attempt")
	}
	docker := func(args ...string) (string, error) {
		command := exec.CommandContext(ctx, "/opt/neticora-runnerd-lab/docker-29.9.3/bin/docker", append([]string{"-H", "unix:///run/runnerd09-docker.sock"}, args...)...)
		out, err := command.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	image, err := docker("image", "inspect", "--format", "{{.Id}}", "runner-github-kata:runnerd09-block-v2-20261107")
	if err != nil {
		t.Fatal(err, image)
	}
	m := blockFixture()
	m.Qualified = false
	m.Acceptance = nil
	m.ImageDigest = image
	m.HostKernel = strings.TrimSpace(mustLabRead(t, "/proc/sys/kernel/osrelease"))
	m.QEMUBinary = "/opt/kata/bin/qemu-system-x86_64"
	m.ShimBinary = "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2"
	m.VMNamePrefix = "sandbox-"
	m.DockerConfig = "/etc/neticora-runnerd09-lab/docker.json"
	m.RuntimeConfig = "/etc/neticora-runnerd09-lab/configuration-qemu.toml"
	m.GuestKernel = "/opt/kata/share/kata-containers/vmlinuz-6.18.35-202"
	m.GuestImage = "/opt/kata/share/kata-containers/kata-ubuntu-resolute.image"
	formatter, err := filepath.EvalSymlinks("/usr/sbin/mkfs.ext4")
	if err != nil {
		t.Fatal(err)
	}
	m.Files = map[string]string{}
	for _, path := range []string{m.QEMUBinary, m.ShimBinary, m.DockerConfig, m.RuntimeConfig, m.GuestKernel, m.GuestImage, formatter, "/etc/mke2fs.conf"} {
		sum := sha256.Sum256([]byte(mustLabRead(t, path)))
		m.Files[path] = hex.EncodeToString(sum[:])
	}
	filesystem := func(root, serial string) Filesystem {
		var st syscall.Stat_t
		var fs syscall.Statfs_t
		if syscall.Stat(root, &st) != nil || syscall.Statfs(root, &fs) != nil {
			t.Fatal("missing qualified lab filesystem")
		}
		uuid, err := exec.Command("blkid", "-s", "UUID", "-o", "value", "/dev/disk/by-id/virtio-"+serial).Output()
		if err != nil {
			t.Fatal(err)
		}
		return Filesystem{Root: root, Device: uint64(st.Dev), Bytes: uint64(fs.Blocks) * uint64(fs.Bsize), UUID: strings.TrimSpace(string(uuid)), BackingDevice: "/dev/disk/by-id/virtio-" + serial}
	}
	m.Storage.Block.Pool = filesystem("/var/lib/neticora-runnerd-kata-block", "neticora-r9-pool-01")
	m.Storage.Runtime = filesystem("/var/lib/neticora-runnerd-kata-runtime", "neticora-r9-state-01")
	m.SandboxRoots = []string{m.Storage.Runtime.Root + "/kata-containers", m.Storage.Runtime.Root + "/kata-containers/shared/sandboxes", m.Storage.Runtime.Root + "/vc/sbs", m.Storage.Runtime.Root + "/vc/vm"}
	m.Storage.DockerRoot = "/var/lib/runnerd09-docker"
	m.Storage.Block.Bytes = 4 << 30
	m.Storage.Block.MkfsBinary = formatter
	m.Storage.Block.DeviceDirectory = "/run/neticora-runnerd09-lab/devices"
	m.GuestCapabilities = []string{"SYS_ADMIN", "NET_ADMIN", "MKNOD", "DAC_OVERRIDE", "CHOWN", "FOWNER", "FSETID", "SETUID", "SETGID", "SETPCAP", "SYS_CHROOT", "NET_RAW", "NET_BIND_SERVICE", "SETFCAP", "KILL", "AUDIT_WRITE"}
	m.Budget.Guest.MemoryBytes = "2147483648"
	m.Budget.Effective.MemoryBytes = "2684354560"
	m.Budget.Overhead.MemoryBytes = "536870912"
	m.Budget.Guest.StorageBytes = strconv.FormatUint(m.Storage.Block.Bytes, 10)
	total := m.Storage.Block.Pool.Bytes + m.Storage.Runtime.Bytes + m.Storage.OuterBytes + m.Storage.LogBytes
	m.Budget.Effective.StorageBytes = strconv.FormatUint(total, 10)
	m.Budget.Overhead.StorageBytes = strconv.FormatUint(total-m.Storage.Block.Bytes, 10)
	p := profile(m)
	p.EvidenceDirectory = base + "/evidence"
	p.JournalDirectory = base + "/journal"
	p.Base.BootstrapRoot = "/run/neticora-runnerd09-lab/bootstrap"
	scope := agent.StoreScope{InstallationID: "runnerd09-unqualified-lab", TenantID: "lab", HostID: "lab", EndpointIdentity: m.EndpointIdentity}
	spec := protocol.ExecutionSpec{ExecutionId: "runnerd09-block-live-" + attempt, AttemptId: "lab-" + attempt, Generation: "1", SpecHash: strings.Repeat("e", 64), IsolationProfile: "isolated", ProfileVersion: p.ID, TemplateVersion: BlockTemplate, ImageDigest: image, Resources: m.Budget.Effective}
	plan, err := p.Plan(scope, spec)
	if err != nil {
		t.Fatal(err)
	}
	report := map[string]any{"scope": "unqualified-lab-no-platform-admission", "qualified": false, "fault": fault, "name": plan.Name, "image": image, "phase": "allocation-intent"}
	save := func() {
		t.Helper()
		raw, e := json.MarshalIndent(report, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		tmp := ledger + ".pending"
		f, e := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(raw); e != nil {
			t.Fatal(e)
		}
		if e = f.Sync(); e != nil {
			t.Fatal(e)
		}
		f.Close()
		if e = os.Rename(tmp, ledger); e != nil {
			t.Fatal(e)
		}
		root, e := hostfs.OpenState(base)
		if e != nil {
			t.Fatal(e)
		}
		defer root.Close()
		if e = syncRoot(root); e != nil {
			t.Fatal(e)
		}
	}
	save()
	if err = p.prepareBlock(ctx, plan); err != nil {
		t.Fatal("allocation:", err)
	}
	record, err := p.blockRecord(plan)
	if err != nil {
		t.Fatal(err)
	}
	report["allocation"] = record
	report["phase"] = "allocated"
	save()
	script := mustLabRead(t, "testdata/kata_guest_block_probe.py")
	args := []string{"create", "--pull=never", "--name", plan.Name, "--runtime", "neticora-kata-rs-qemu", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--memory", "2560m", "--memory-swap", "2560m", "--cpus", "1.25", "--pids-limit", "128", "--storage-opt", "size=1073741824", "--tmpfs", "/run:rw,nosuid,nodev,size=134217728"}
	for _, capability := range m.GuestCapabilities {
		args = append(args, "--cap-add", capability)
	}
	for key, value := range plan.Config.Labels {
		args = append(args, "--label", key+"="+value)
	}
	args = append(args, "--device", p.blockNode(plan.Name)+":/dev/neticora-execution:rw", "--entrypoint", "/usr/bin/python3", image, "-c", script, plan.Config.Cmd[1])
	id, err := docker(args...)
	if err != nil {
		t.Fatal("create:", err, id)
	}
	report["containerId"] = id
	report["phase"] = "created"
	save()
	if out, err := docker("start", id); err != nil {
		t.Fatal("start:", err, out)
	}
	report["phase"] = "started"
	save()
	if err := p.Capture(ctx, id, plan); err != nil {
		t.Fatal("trusted VMM capture:", err)
	}
	report["phase"] = "captured"
	save()
	if fault == "guest-kill" {
		report["phase"] = "guest-kill-intent"
		save()
		if text, e := docker("kill", "--signal", "KILL", id); e != nil {
			t.Fatal("owned guest kill:", e, text)
		}
	}
	out, err := docker("wait", id)
	logs, _ := docker("logs", id)
	report["guestLogs"] = logs
	report["containerExit"] = out
	report["phase"] = "cleanup-intent"
	save()
	if err != nil {
		t.Fatal("wait:", err, out)
	}
	// Only this exact recorded container is removed. Production reservation/state
	// transitions are deliberately outside this diagnostic's acceptance scope.
	inspected, err := docker("inspect", "--format", "{{index .Config.Labels \"com.neticora.runnerd.execution\"}}", id)
	if err != nil || inspected != spec.ExecutionId {
		t.Fatal("container identity changed")
	}
	if output, err := docker("rm", id); err != nil {
		t.Fatal(err, output)
	}
	if fault == "held-mmap" || fault == "interrupted-unlink" {
		file, e := os.OpenFile(p.rawPath(plan.Name), os.O_RDWR, 0)
		if e != nil {
			t.Fatal(e)
		}
		var st syscall.Stat_t
		if syscall.Fstat(int(file.Fd()), &st) != nil || st.Ino != record.FileInode || uint64(st.Dev) != record.FileDevice {
			file.Close()
			t.Fatal("owned backing identity changed")
		}
		mapped, e := syscall.Mmap(int(file.Fd()), 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
		file.Close()
		if e != nil {
			t.Fatal(e)
		}
		defer func() {
			if mapped != nil {
				_ = syscall.Munmap(mapped)
			}
		}()
		if e = p.VerifyAbsent(ctx, id, plan); e == nil {
			t.Fatal("live mapped backing released")
		}
		held, e := p.blockRecord(plan)
		if e != nil || held.Phase != "releasing" {
			t.Fatal("cleanup intent not retained", e)
		}
		report["mappedReferenceHeldRelease"] = true
		report["phase"] = "reference-held"
		save()
		if fault == "interrupted-unlink" {
			// The owned cleanup intent is durable. Simulate interruption after its
			// unlink while the old inode remains mapped. No metadata fact is edited.
			pool, e := hostfs.OpenState(m.Storage.Block.Pool.Root)
			if e != nil {
				t.Fatal(e)
			}
			if e = pool.Remove(plan.Name + ".raw"); e != nil {
				pool.Close()
				t.Fatal(e)
			}
			if e = syncRoot(pool); e != nil {
				pool.Close()
				t.Fatal(e)
			}
			pool.Close()
			report["phase"] = "owned-unlink-interrupted"
			save()
			if e = p.VerifyAbsent(ctx, id, plan); e == nil {
				t.Fatal("mapped deleted backing released")
			}
			report["deletedMappingHeldRelease"] = true
			save()
		}
		if e = syscall.Munmap(mapped); e != nil {
			t.Fatal(e)
		}
		mapped = nil
	}
	if err := p.VerifyAbsent(ctx, id, plan); err != nil {
		t.Fatal("physical teardown:", err)
	}
	final, err := p.blockRecord(plan)
	if err != nil || final.Phase != "released" {
		t.Fatal("allocation not released", err)
	}
	report["phase"] = "physical-disposal-verified"
	report["released"] = final
	save()
	if fault == "guest-kill" {
		if out != "137" {
			t.Fatalf("kill injection not established: exit=%s", out)
		}
		t.Log("Guest SIGKILL retained scoped ownership through verified physical disposal")
		return
	}
	if out != "0" || !strings.Contains(logs, "native-docker-build-passed") {
		t.Fatalf("guest build failed; disposal completed safely: exit=%s logs=%s", out, logs)
	}
	t.Log("Real loop/virtio-blk/ext4/overlay2 build and backend disposal passed; unqualified lab only")
}
func mustLabRead(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(fmt.Errorf("read lab input %s: %w", path, err))
	}
	return string(raw)
}

func TestRunnerd09LiveRuntimeRegistration(t *testing.T) {
	if os.Getenv("RUNNERD09_LIVE_LAB") != "1" {
		t.Skip("explicit isolated lab required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required for bound peer evidence")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	engine, err := dockerengine.OpenReadOnly("unix:///run/runnerd09-docker.sock", "runnerd09-unqualified-lab", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	config := "/etc/neticora-runnerd09-lab/docker.json"
	sum := sha256.Sum256([]byte(mustLabRead(t, config)))
	hash := hex.EncodeToString(sum[:])
	check := func(digest, path string) error {
		return engine.CheckKataTuple(ctx, "neticora-kata-rs-qemu", "29.9.3", "/var/lib/runnerd09-docker", "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2", path, config, digest)
	}
	if err := check(hash, "/etc/neticora-runnerd09-lab/configuration-qemu.toml"); err != nil {
		t.Fatal("pinned active configuration refused:", err)
	}
	if err := check(strings.Repeat("0", 64), "/etc/neticora-runnerd09-lab/configuration-qemu.toml"); err == nil {
		t.Fatal("wrong config digest accepted")
	}
	if err := check(hash, "/other-runtime.toml"); err == nil {
		t.Fatal("different runtime configuration accepted")
	}
	t.Log("Opaque Docker runtime registration verified against bound peer and pinned startup config; negative substitutions rejected")
}
