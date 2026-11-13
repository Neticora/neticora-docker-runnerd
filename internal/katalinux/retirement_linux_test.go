//go:build linux

package katalinux

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/moby/moby/api/types/container"
)

func retirementFixture(t *testing.T) (*Profile, string, dockerengine.Plan, string) {
	t.Helper()
	p := profile(multiBlockFixture())
	p.Manifest.RetirementPolicy = RetirementPolicy
	p.brokerOwned = true
	p.EvidenceDirectory = t.TempDir()
	p.Manifest.Storage.Runtime.Root = t.TempDir()
	if err := os.Chmod(p.Manifest.Storage.Runtime.Root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p.EvidenceDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	name := "nrd-" + strings.Repeat("a", 64)
	plan := dockerengine.Plan{Name: name, Config: &container.Config{Labels: map[string]string{dockerengine.LabelPrefix + "spec": strings.Repeat("b", 64), dockerengine.LabelPrefix + "generation": "1"}}, HostConfig: &container.HostConfig{Resources: container.Resources{CgroupParent: hostCgroupUnit(name)}}}
	boot, err := currentCgroupBoot()
	if err != nil {
		t.Fatal(err)
	}
	group := CgroupRecord{Version: "runnerd09-host-cgroup-v1", Profile: p.ID, Name: name, Unit: hostCgroupUnit(name), Path: hostCgroupPath(name), Owner: strings.Repeat("c", 64), BootID: boot, Device: 1, Inode: 2, CPUQuota: 1250000, MemoryBytes: 2684354560, PidsLimit: p.Manifest.HostCgroup.PidsLimit, Phase: "ready"}
	// Derive exact fixture budgets, independent of production numbers.
	root, err := hostfs.OpenState(p.EvidenceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	// The full record parser checks these against the fixture budget.
	group.CPUQuota = 1250000
	group.MemoryBytes = 2684354560
	// multiBlockFixture is shared with the cgroup tests; use a matching record helper below.
	group = retirementFixtureLimits(p, group)
	if err = p.persistCgroup(group); err != nil {
		t.Fatal(err)
	}
	id, op := strings.Repeat("d", 64), strings.Repeat("e", 64)
	original := Evidence{Version: "runnerd09-physical-v1", Profile: p.ID, Container: id, SpecHash: plan.Config.Labels[dockerengine.LabelPrefix+"spec"], Generation: "1", Cgroup: &group, Prepared: true}
	if err = persist(root, name+".json", original); err != nil {
		t.Fatal(err)
	}
	return p, id, plan, op
}
func TestRetirementOriginalAuthorityAndPermanentFence(t *testing.T) {
	p, id, plan, op := retirementFixture(t)
	if err := p.RequireAcquisition(plan); err != nil {
		t.Fatal(err)
	}
	if err := p.BeginRetirement(id, plan, op); err != nil {
		t.Fatal(err)
	}
	before, err := p.retirementRecord(plan)
	if err != nil {
		t.Fatal(err)
	}
	if before.Phase != "INTENT" || before.Quarantined {
		t.Fatal(before)
	}
	if p.RequireAcquisition(plan) == nil {
		t.Fatal("retired attempt reacquired")
	}
	if p.BeginRetirement(id, plan, strings.Repeat("f", 64)) == nil {
		t.Fatal("replacement authority accepted")
	}
	if p.BeginRetirement(strings.Repeat("f", 64), plan, op) == nil {
		t.Fatal("replacement resource accepted")
	}
	if err = p.BeginRetirement(id, plan, op); err != nil {
		t.Fatal(err)
	}
	after, err := p.retirementRecord(plan)
	if err != nil || after.OperationID != before.OperationID || after.Cgroup != before.Cgroup {
		t.Fatal("ownership changed", err)
	}
	// A private policy flag alone cannot authorize deletion.
	if p.VerifyAbsent(context.Background(), id, plan) == nil {
		t.Fatal("unfenced new policy reached legacy reclamation")
	}
	if err = p.CapturePrepared(id, plan); err == nil {
		t.Fatal("replacement capture overwrote original witness")
	}
}
func TestRetirementCorruptionAndMissingOriginalFailClosed(t *testing.T) {
	for _, which := range []string{"missing-original", "corrupt-tombstone", "foreign-profile", "foreign-generation"} {
		t.Run(which, func(t *testing.T) {
			p, id, plan, op := retirementFixture(t)
			if which == "missing-original" {
				if err := os.Remove(filepath.Join(p.EvidenceDirectory, plan.Name+".json")); err != nil {
					t.Fatal(err)
				}
				if p.BeginRetirement(id, plan, op) == nil {
					t.Fatal("ownership backfilled")
				}
				return
			}
			if err := p.BeginRetirement(id, plan, op); err != nil {
				t.Fatal(err)
			}
			switch which {
			case "corrupt-tombstone":
				if err := os.WriteFile(filepath.Join(p.EvidenceDirectory, plan.Name+".retirement.json"), []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-profile":
				p.ID += "foreign"
			case "foreign-generation":
				plan.Config.Labels[dockerengine.LabelPrefix+"generation"] = "2"
			}
			if p.RequireAcquisition(plan) == nil {
				t.Fatal("uncertain record became capacity")
			}
			if p.BeginRetirement(id, plan, op) == nil {
				t.Fatal("uncertain ownership adopted")
			}
		})
	}
}
func TestRetirementUnverifiedFenceKeepsIntent(t *testing.T) {
	p, id, plan, op := retirementFixture(t)
	if err := p.BeginRetirement(id, plan, op); err != nil {
		t.Fatal(err)
	}
	_, err := p.FenceRetirement(context.Background(), id, plan, op, func() error { return ErrQualification })
	if err == nil {
		t.Fatal("failed physical guard accepted")
	}
	r, err := p.retirementRecord(plan)
	if err != nil || r.Phase != "INTENT" || !r.Quarantined || r.FencedAt != "" {
		t.Fatal("quarantine lost original phase", r, err)
	}
	if p.RequireAcquisition(plan) == nil {
		t.Fatal("quarantined attempt reacquired")
	}
}

func retirementFixtureLimits(p *Profile, g CgroupRecord) CgroupRecord {
	cpu, _ := strconv.ParseUint(p.Manifest.Budget.Effective.CpuMillis, 10, 64)
	memory, _ := strconv.ParseUint(p.Manifest.Budget.Effective.MemoryBytes, 10, 64)
	g.CPUQuota = cpu * 1000
	g.MemoryBytes = memory
	return g
}

func TestRetirementReclaimedRevokesReclamation(t *testing.T) {
	p, id, plan, op := retirementFixture(t)
	if err := p.BeginRetirement(id, plan, op); err != nil {
		t.Fatal(err)
	}
	r, err := p.retirementRecord(plan)
	if err != nil {
		t.Fatal(err)
	}
	r.Phase = "RECLAIMED"
	r.FencedAt = "2026-11-12T00:00:00Z"
	if err = p.persistRetirement(r); err != nil {
		t.Fatal(err)
	}
	f := &retirementFence{profile: p, plan: plan, record: r}
	if f.reclaim(t.Context()) == nil {
		t.Fatal("released barrier regained reclamation authority")
	}
	if p.RequireAcquisition(plan) == nil {
		t.Fatal("reclaimed attempt gained launch authority")
	}
	if err = p.BeginRetirement(id, plan, op); err != nil {
		t.Fatal(err)
	}
	after, err := p.retirementRecord(plan)
	if err != nil || after.Phase != "RECLAIMED" {
		t.Fatal("idempotent begin regressed phase", err)
	}
	if p.ReclaimRetired(t.Context(), id, plan, op, nil) == nil {
		t.Fatal("missing independent runtime guard accepted")
	}
	if p.quarantineRetirement(plan, id, op) != nil {
		t.Fatal("quarantine persistence failed")
	}
	after, err = p.retirementRecord(plan)
	if err != nil || after.Phase != "RECLAIMED" || !after.Quarantined {
		t.Fatal("quarantine regressed durable reclamation", err)
	}
}

func TestRetirementAcquisitionRequiresPrivateAnchors(t *testing.T) {
	for _, kind := range []string{"missing-evidence", "public-metadata"} {
		t.Run(kind, func(t *testing.T) {
			p, _, plan, _ := retirementFixture(t)
			if kind == "missing-evidence" {
				p.EvidenceDirectory += "/missing"
			} else if err := os.Chmod(p.Manifest.Storage.Runtime.Root, 0755); err != nil {
				t.Fatal(err)
			}
			if p.RequireAcquisition(plan) == nil {
				t.Fatal("unsafe acquisition boundary accepted")
			}
		})
	}
}
