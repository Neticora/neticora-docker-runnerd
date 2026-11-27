//go:build linux && runnerd_qualification

package katalinux

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

// Initializes only a new empty disposable pool through the ordinary ownership
// writer. It cannot reset an existing index or adopt historical allocations.
func TestPhaseFCleanPoolInitializationLab(t *testing.T) {
	seed := os.Getenv("RUNNERD_F_CLEAN_POOL_SEED")
	if seed == "" {
		t.Skip("explicit new clean-pool fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root lab coordinator required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal(err)
	}
	raw, err := hostfs.ReadPrivate(seed, 131072)
	if err != nil {
		t.Fatal(err)
	}
	var envelope LabEnvelope
	if json.Unmarshal(raw, &envelope) != nil || envelope.Manifest.Version != MultiBlockVersion || envelope.Manifest.Qualified || len(envelope.Manifest.Acceptance) != 0 || envelope.Manifest.Storage.Block == nil {
		t.Fatal("unqualified v3 lab seed required")
	}
	m := envelope.Manifest
	poolPath := m.Storage.Block.Pool.Root
	evidence := os.Getenv("RUNNERD_F_CLEAN_POOL_EVIDENCE")
	journal := os.Getenv("RUNNERD_F_CLEAN_POOL_JOURNAL")
	for _, path := range []string{poolPath, evidence, journal} {
		if filepath.Clean(path) != path || !strings.HasPrefix(path, "/var/lib/neticora-runnerd09-f-") {
			t.Fatal("new Phase F directories required")
		}
	}
	devices := []string{"/dev/disk/by-id/virtio-neticora-r9-f-pool-0", "/dev/disk/by-id/virtio-neticora-r9-f2pool-1"}
	if poolPath == evidence || poolPath == journal || evidence == journal || !slices.Contains(devices, m.Storage.Block.Pool.BackingDevice) {
		t.Fatal("separate directories and dedicated new disk required")
	}
	if err := verifyPersistentVolume(m.Storage.Block.Pool, m.Storage.Block.Pool.Device); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{poolPath, evidence, journal} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if directory != poolPath || entry.Name() != "lost+found" || !entry.IsDir() {
				t.Fatal("pool/evidence/journal must be new and empty; never reset", directory, entry.Name())
			}
		}
	}
	pool, err := hostfs.OpenState(poolPath)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	root, err := hostfs.OpenState(evidence)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	p := &Profile{Manifest: m, EvidenceDirectory: evidence, JournalDirectory: journal}
	lock, err := p.lockBlockPool()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := p.ensureBlockPoolOwner(pool, root); err != nil {
		t.Fatal(err)
	}
	t.Log("new isolated pool ownership initialized; no historical pool or allocation changed; production admission false")
}
