//go:build linux && runnerd_kata

package katalinux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/moby/moby/api/types/container"
)

// Empty transient-unit lifecycle only. Real VMM placement, load enforcement,
// restart and journal/platform correlation remain independent live gates.
func TestRunnerd09LiveHostCgroupLifecycle(t *testing.T) {
	if os.Getenv("RUNNERD09_LIVE_LAB") != "1" {
		t.Skip("explicit disposable root/systemd lab required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root disposable lab required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal("lab marker required")
	}
	attempt := os.Getenv("RUNNERD09_LAB_ATTEMPT")
	if !regexp.MustCompile(`^[a-zA-Z0-9-]{1,48}$`).MatchString(attempt) {
		t.Fatal("unique explicit lab attempt required")
	}
	fault := os.Getenv("RUNNERD09_CGROUP_LAB_FAULT")
	if fault != "" && fault != "lost-create-reply" && fault != "lost-stop-reply" {
		t.Fatal("unsupported empty-unit lab fault")
	}
	recoverOnly := os.Getenv("RUNNERD09_CGROUP_LAB_RECOVER_ONLY")
	if recoverOnly != "" && recoverOnly != "1" {
		t.Fatal("unsupported empty-unit recovery mode")
	}
	m := multiBlockFixture()
	m.Qualified = false
	m.HostCgroup.SystemctlBinary, m.HostCgroup.BusctlBinary = "/usr/bin/systemctl", "/usr/bin/busctl"
	for _, binary := range []string{m.HostCgroup.SystemctlBinary, m.HostCgroup.BusctlBinary} {
		raw, err := os.ReadFile(binary)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(raw)
		m.Files[binary] = hex.EncodeToString(hash[:])
	}
	if fault != "" {
		// The pinned wrapper exists only in this unqualified test authority's
		// fixture, never in a shipping descriptor or production environment.
		body := "#!/bin/sh\n/usr/bin/busctl \"$@\"\nresult=$?\n[ \"$result\" -ne 0 ] && exit \"$result\"\nexit 75\n"
		if fault == "lost-stop-reply" {
			body = "#!/bin/sh\nlost=0\nfor arg do [ \"$arg\" = stop ] && lost=1; done\n/usr/bin/systemctl \"$@\"\nresult=$?\n[ \"$result\" -ne 0 ] && exit \"$result\"\n[ \"$lost\" -eq 1 ] && exit 75\nexit 0\n"
		}
		root, err := hostfs.OpenState("/var/lib/neticora-runnerd09-lab/evidence")
		if err != nil {
			t.Fatal(err)
		}
		name := "cgroup-lab-" + attempt + "-" + fault + ".sh"
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
		if errors.Is(err, os.ErrExist) {
			prior, e := root.ReadFile(name)
			if e != nil || string(prior) != body {
				root.Close()
				t.Fatal("prior wrapper requires explicit reconciliation")
			}
		} else if err == nil {
			_, err = file.WriteString(body)
			if err == nil {
				err = file.Sync()
			}
			err = errors.Join(err, file.Close(), syncRoot(root))
		}
		root.Close()
		if err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
		binary := filepath.Join("/var/lib/neticora-runnerd09-lab/evidence", name)
		hash := sha256.Sum256([]byte(body))
		m.Files[binary] = hex.EncodeToString(hash[:])
		if fault == "lost-create-reply" {
			m.HostCgroup.BusctlBinary = binary
		} else {
			m.HostCgroup.SystemctlBinary = binary
		}
	}
	p := profile(m)
	p.EvidenceDirectory = "/var/lib/neticora-runnerd09-lab/evidence"
	hash := sha256.Sum256([]byte("runnerd09-empty-cgroup-lab:" + attempt + ":" + fault))
	name := "nrd-" + hex.EncodeToString(hash[:])
	plan := dockerengine.Plan{Name: name, HostConfig: &container.HostConfig{Resources: container.Resources{CgroupParent: hostCgroupUnit(name)}}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if recoverOnly == "1" {
		// Reconcile only an existing exact attempt through production cleanup.
		// Never call preparation: cleanup recovery cannot create another unit.
		if _, err := p.cgroupRecord(plan); err != nil {
			t.Fatal("existing scoped cleanup intent required", err)
		}
		settleSandboxTest(t, func() error {
			released, err := p.releaseHostCgroup(ctx, plan)
			if err != nil {
				return err
			}
			return p.checkReleasedHostCgroup(ctx, plan, released)
		})
		t.Log("Existing empty-unit intent physically reconciled; cleanup-only recovery is not a fault-test pass")
		return
	}
	err := p.prepareHostCgroup(ctx, plan)
	if fault == "lost-create-reply" {
		if err == nil {
			t.Fatal("lost create response not injected")
		}
		record, e := p.cgroupRecord(plan)
		if e != nil || record.Phase != "creating" {
			t.Fatal("lost response discarded creation intent", e)
		}
		// StartTransientUnit returns a queued job before the kernel cgroup
		// necessarily exists. Observe that exact unit becoming ready before
		// testing retry identity; never issue another create to satisfy the wait.
		var before syscall.Stat_t
		settleSandboxTest(t, func() error {
			status, e := p.cgroupUnitStatus(ctx, plan.Name)
			if e != nil {
				return e
			}
			if status["ActiveState"] != "active" || status["Transient"] != "yes" || status["ControlGroup"] != record.Path || status["Description"] != cgroupDescription(record) {
				return ErrQualification
			}
			var populated bool
			before, populated, e = inspectCgroup(record)
			if populated {
				return ErrQualification
			}
			return e
		})
		if err = p.prepareHostCgroup(ctx, plan); err != nil {
			t.Fatal("lost response retry did not reconcile same unit", err)
		}
		after, e := p.cgroupRecord(plan)
		if e != nil || after.Inode != before.Ino || after.Device != uint64(before.Dev) {
			t.Fatal("lost response recreated unit", e)
		}
	}
	if err != nil {
		t.Fatal("owned host slice preparation", err)
	}
	first, err := p.verifyHostCgroup(ctx, plan, nil)
	if err != nil {
		t.Fatal("exact kernel limit verification", err)
	}
	if err = p.prepareHostCgroup(ctx, plan); err != nil {
		t.Fatal("idempotent same-unit preparation", err)
	}
	again, err := p.verifyHostCgroup(ctx, plan, nil)
	if err != nil || !sameHostCgroup(first, again) {
		t.Fatal("unit identity changed", err)
	}
	released, err := p.releaseHostCgroup(ctx, plan)
	if fault == "lost-stop-reply" {
		if err == nil {
			t.Fatal("lost stop response not injected")
		}
		record, e := p.cgroupRecord(plan)
		if e != nil || record.Phase != "releasing" {
			t.Fatal("lost stop response discarded cleanup intent", e)
		}
		released, err = p.releaseHostCgroup(ctx, plan)
	}
	if err != nil || released == nil || released.Phase != "released" {
		t.Fatal("empty owned unit cleanup", err)
	}
	if p.checkReleasedHostCgroup(ctx, plan, released) != nil {
		t.Fatal("kernel and unit absence not verified")
	}
	if p.prepareHostCgroup(ctx, plan) == nil {
		t.Fatal("released same attempt recreated")
	}
	t.Log("Pinned systemd transient slice: exact hard CPU/memory/swap/PID limits, stable ownership and verified empty cleanup; unqualified lab only")
}
