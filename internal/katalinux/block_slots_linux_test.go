//go:build linux

package katalinux

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/moby/moby/api/types/container"
)

func multiBlockFixture() Manifest {
	m := blockFixture()
	m.Version = MultiBlockVersion
	m.GuestDNSServers = []string{"192.0.2.53"}
	m.HostCgroup = &HostCgroup{Method: "systemd-transient-slice-v1", SystemctlBinary: "/qualified/systemctl", BusctlBinary: "/qualified/busctl", PidsLimit: 512}
	m.Files[m.HostCgroup.SystemctlBinary] = strings.Repeat("e", 64)
	m.Files[m.HostCgroup.BusctlBinary] = strings.Repeat("f", 64)
	m.Storage.Block.Pool.Bytes = 6 << 30
	m.Storage.Block.MaxConcurrentAllocations = 2
	m.Storage.Block.PoolReservationBytes = (2 << 30) + (256 << 20)
	return m
}

func multiBlockState(t *testing.T) (*Profile, *os.Root, *os.Root) {
	t.Helper()
	m := multiBlockFixture()
	m.Storage.Block.Pool.Root = t.TempDir()
	p := profile(m)
	p.EvidenceDirectory = t.TempDir()
	p.JournalDirectory = filepath.Join(t.TempDir(), "journal")
	root, err := os.OpenRoot(p.EvidenceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := os.OpenRoot(m.Storage.Block.Pool.Root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close(); pool.Close() })
	if err = p.ensureBlockPoolOwner(pool, root); err != nil {
		t.Fatal(err)
	}
	return p, root, pool
}

func slotClaim(p *Profile, letter string) BlockRecord {
	name := "nrd-" + strings.Repeat(letter, 64)
	return BlockRecord{Version: "runnerd09-block-allocation-v1", Profile: p.ID, Name: name,
		Labels: map[string]string{"com.neticora.runnerd.execution": name}, Phase: "claiming",
		UUID: p.blockUUID(name), Bytes: p.Manifest.Storage.Block.Bytes, BootID: "unit-only"}
}

func TestMultiBlockProfileBoundsAggregatePhysicalReservation(t *testing.T) {
	m := multiBlockFixture()
	if err := profile(m).validate(); err != nil {
		t.Fatal(err)
	}
	if profile(m).MaxConcurrentAllocations() != 2 {
		t.Fatal("signed concurrency lost")
	}
	id, _ := ProfileID(m)
	// Shared with Alpha's synthetic-kata-multi.json boundary fixture. Any
	// intentional wire change must update both conformance expectations.
	if id != "docker-kata-rs-qemu-v3-887671cc0e893390424c3789343e9ad10ff52808c85b3c60a12e54ad24778f8f" {
		t.Fatal("Go/platform synthetic profile identity drift", id)
	}
	if !strings.HasPrefix(id, "docker-kata-rs-qemu-v3-") {
		t.Fatal("ambiguous multi-guest profile identity")
	}
	for name, mutate := range map[string]func(*Manifest){
		"missing limit":                   func(m *Manifest) { m.Storage.Block.MaxConcurrentAllocations = 0 },
		"unbounded limit":                 func(m *Manifest) { m.Storage.Block.MaxConcurrentAllocations = 17 },
		"undercharged disk":               func(m *Manifest) { m.Storage.Block.PoolReservationBytes = m.Storage.Block.Bytes },
		"aggregate overcommit":            func(m *Manifest) { m.Storage.Block.PoolReservationBytes = 4 << 30 },
		"v2 cannot claim v3 semantics":    func(m *Manifest) { m.Version = BlockVersion },
		"missing guest DNS":               func(m *Manifest) { m.GuestDNSServers = nil },
		"unreachable Docker loopback DNS": func(m *Manifest) { m.GuestDNSServers = []string{"127.0.0.11"} },
		"DNS command injection":           func(m *Manifest) { m.GuestDNSServers = []string{"192.0.2.53\nnameserver 1.1.1.1"} },
	} {
		t.Run(name, func(t *testing.T) {
			m := multiBlockFixture()
			mutate(&m)
			if profile(m).validate() == nil {
				t.Fatal("unsafe pool accepted")
			}
		})
	}
}

func TestMultiBlockProfileRequiresExplicitReviewedNestedDockerCapabilities(t *testing.T) {
	m := multiBlockFixture()
	m.GuestCapabilities = []string{"SETUID", "SETGID", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE", "NET_RAW", "SETFCAP", "SETPCAP", "SYS_CHROOT", "AUDIT_WRITE", "SYS_ADMIN", "NET_ADMIN"}
	if err := profile(m).validate(); err != nil {
		t.Fatal("reviewable nested Docker guest capability set rejected", err)
	}
	m.GuestCapabilities = append(m.GuestCapabilities, "SYS_MODULE")
	if profile(m).validate() == nil {
		t.Fatal("host-level module administration vocabulary accepted")
	}
}

func TestMultiBlockClaimsSurviveReopenAndEnforceCountAndBytes(t *testing.T) {
	p, root, _ := multiBlockState(t)
	a, b, c := slotClaim(p, "a"), slotClaim(p, "b"), slotClaim(p, "c")
	for _, r := range []BlockRecord{a, b} {
		if err := p.writeActiveBlock(root, r); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := os.OpenRoot(p.EvidenceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	index, err := p.readBlockSlots(reopened)
	if err != nil || len(index.Active) != 2 || index.Active[a.Name].Record.UUID == index.Active[b.Name].Record.UUID {
		t.Fatal("durable claims lost or shared", err)
	}
	if p.writeActiveBlock(root, c) == nil {
		t.Fatal("third execution admitted")
	}
	p.Manifest.Storage.Block.MaxConcurrentAllocations = 3 // Writer also checks bytes independently of admission validation.
	if p.writeActiveBlock(root, c) == nil {
		t.Fatal("aggregate byte overcommit admitted")
	}
}

func TestMultiBlockReleaseNeedsOwnDurableTombstoneAndKeepsPeerReservation(t *testing.T) {
	p, root, _ := multiBlockState(t)
	a, b := slotClaim(p, "a"), slotClaim(p, "b")
	for _, r := range []BlockRecord{a, b} {
		if err := p.writeActiveBlock(root, r); err != nil {
			t.Fatal(err)
		}
	}
	a.Phase = "released"
	if p.writeActiveBlock(root, a) == nil {
		t.Fatal("reservation released without durable final fact")
	}
	// Metadata transaction test only; physical absence is independently checked
	// by releaseBlock before production writes this final tombstone.
	if err := writeBlockState(root, a.Name+".block.json", a); err != nil {
		t.Fatal(err)
	}
	if err := p.writeActiveBlock(root, a); err != nil {
		t.Fatal(err)
	}
	index, err := p.readBlockSlots(root)
	if err != nil || len(index.Active) != 1 || index.Active[b.Name].Record.UUID != b.UUID || index.Active[b.Name].ReservedBytes != p.poolReservationBytes() {
		t.Fatal("peer reservation changed", err)
	}
	if err := p.writeActiveBlock(root, slotClaim(p, "c")); err != nil {
		t.Fatal("verified released slot not reusable", err)
	}
}

func TestMultiBlockPoolRejectsIndependentObserverIndex(t *testing.T) {
	p, root, pool := multiBlockState(t)
	if err := p.ensureBlockPoolOwner(pool, root); err != nil {
		t.Fatal(err)
	}
	other := *p
	other.EvidenceDirectory = t.TempDir()
	foreign, err := os.OpenRoot(other.EvidenceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	if other.ensureBlockPoolOwner(pool, foreign) == nil {
		t.Fatal("second observer bypassed outstanding pool ownership")
	}
}

func TestMissingPoolOwnerWithActiveClaimsCannotBeReinitialized(t *testing.T) {
	p, root, pool := multiBlockState(t)
	if err := p.writeActiveBlock(root, slotClaim(p, "a")); err != nil {
		t.Fatal(err)
	}
	if err := pool.Remove(blockPoolOwnerFile); err != nil {
		t.Fatal(err)
	}
	if p.ensureBlockPoolOwner(pool, root) == nil {
		t.Fatal("lost pool ownership recreated during active work")
	}
	index, err := p.readBlockSlots(root)
	if err != nil || len(index.Active) != 1 {
		t.Fatal("existing reservation discarded", err)
	}
}

func TestMissingOrCorruptSlotIndexCannotBecomeEmptyCapacity(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "corrupt"}[corrupt], func(t *testing.T) {
			p, root, _ := multiBlockState(t)
			r := slotClaim(p, "a")
			if err := p.writeActiveBlock(root, r); err != nil {
				t.Fatal(err)
			}
			if corrupt {
				if err := root.WriteFile(blockSlotsFile, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := root.Remove(blockSlotsFile); err != nil {
				t.Fatal(err)
			}
			if _, err := p.readBlockSlots(root); err == nil {
				t.Fatal("lost index became empty capacity")
			}
			if p.writeActiveBlock(root, slotClaim(p, "b")) == nil {
				t.Fatal("new work bypassed unknown ownership")
			}
		})
	}
}

func TestCorruptIndexCannotBeHiddenByReleasedExecutionTombstone(t *testing.T) {
	p, root, _ := multiBlockState(t)
	r := slotClaim(p, "a")
	r.Phase = "released"
	if err := writeBlockState(root, r.Name+".block.json", r); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile(blockSlotsFile, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	plan := dockerengine.Plan{Name: r.Name, Config: &container.Config{Labels: r.Labels}}
	if _, err := p.blockRecord(plan); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal("corrupt ownership hidden by tombstone", err)
	}
}
