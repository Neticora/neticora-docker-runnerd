//go:build linux

package katalinux

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/moby/moby/api/types/container"
)

func TestStandaloneLiveAllocation(t *testing.T) {
	backing := os.Getenv("NETICORA_PHASE2_LAB_EXECUTION_DEVICE")
	if backing == "" {
		t.Skip("requires the dedicated runnerd-kata lab")
	}
	if host, err := os.Hostname(); err != nil || host != "neticora-runnerd-kata" || os.Geteuid() != 0 {
		t.Fatal("dedicated runnerd-kata lab root required")
	}
	root := os.Getenv("NETICORA_PHASE2_LAB_RAW_RECOVERY")
	runRoot := os.Getenv("NETICORA_PHASE2_LAB_RAW_RECOVERY_RUN")
	recovering := root != ""
	if recovering {
		if !strings.HasPrefix(root, "/var/tmp/neticora-phase2-raw-") || !strings.HasPrefix(runRoot, "/run/neticora-phase2-raw-") ||
			filepath.Dir(root) != "/var/tmp" || filepath.Dir(runRoot) != "/run" {
			t.Fatal("exact dedicated test paths required")
		}
	} else {
		var err error
		root, err = os.MkdirTemp("/var/tmp", "neticora-phase2-raw-")
		if err != nil {
			t.Fatal(err)
		}
		runRoot, err = os.MkdirTemp("/run", "neticora-phase2-raw-")
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"pool", "runtime", "evidence", "journal"} {
			if err = os.Mkdir(filepath.Join(root, name), 0700); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Logf("test allocation evidence: %s and %s", root, runRoot)
	uuid, err := exec.CommandContext(t.Context(), "/usr/sbin/blkid", "-s", "UUID", "-o", "value", backing).Output()
	if err != nil {
		t.Fatal(err)
	}
	filesystem := func(name string) Filesystem {
		t.Helper()
		path := filepath.Join(root, name)
		var st syscall.Stat_t
		var size syscall.Statfs_t
		if syscall.Stat(path, &st) != nil || syscall.Statfs(path, &size) != nil {
			t.Fatal("cannot inspect lab execution pool")
		}
		return Filesystem{Root: path, Device: uint64(st.Dev), Bytes: uint64(size.Blocks) * uint64(size.Bsize),
			UUID: strings.TrimSpace(string(uuid)), BackingDevice: backing}
	}
	m := multiBlockFixture()
	m.Standalone = true
	m.Storage.Block.Pool = filesystem("pool")
	m.Storage.Runtime = filesystem("runtime")
	m.Storage.Block.DeviceDirectory = filepath.Join(runRoot, "devices")
	m.Storage.Block.MkfsBinary, err = filepath.EvalSymlinks("/usr/sbin/mkfs.ext4")
	if err != nil {
		t.Fatal(err)
	}
	m.HostCgroup.SystemctlBinary, m.HostCgroup.BusctlBinary = "/usr/bin/systemctl", "/usr/bin/busctl"
	for _, file := range []string{m.Storage.Block.MkfsBinary, "/etc/mke2fs.conf", m.HostCgroup.SystemctlBinary, m.HostCgroup.BusctlBinary} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		m.Files[file] = fmt.Sprintf("%x", sha256.Sum256(raw))
	}
	p := profile(m)
	p.EvidenceDirectory, p.JournalDirectory = filepath.Join(root, "evidence"), filepath.Join(root, "journal")
	name := fmt.Sprintf("nrd-%x", sha256.Sum256([]byte(root)))
	plan := dockerengine.Plan{Name: name, Config: &container.Config{Labels: map[string]string{"com.neticora.runnerd.execution": name}},
		HostConfig: &container.HostConfig{Resources: container.Resources{CgroupParent: hostCgroupUnit(name)}}}
	t.Cleanup(func() {
		if err := p.ReleaseStandalone(context.Background(), plan); err != nil {
			t.Error(err)
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
		if err := os.RemoveAll(runRoot); err != nil {
			t.Error(err)
		}
	})
	if recovering {
		return
	}
	if err := p.prepareBlock(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if err := p.VerifyStorage(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if err := p.ReleaseStandalone(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	t.Logf("verified allocation, bounded cgroup, teardown, and idempotent retry for %s", name)
}
