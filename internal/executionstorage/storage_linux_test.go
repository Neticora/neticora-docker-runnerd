//go:build linux

package executionstorage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

func fixture(t *testing.T) (Manager, agent.Identity) { m, id, _ := fixtureAt(t); return m, id }
func fixtureAt(t *testing.T) (Manager, agent.Identity, string) {
	t.Helper()
	root := t.TempDir()
	os.Chmod(root, 0700)
	state := t.TempDir()
	os.Chmod(state, 0700)
	s, err := journal.OpenRecovery(context.Background(), state, journal.Options{ReservationLimits: agent.ReservationLimits{CPUMillis: 100000, MemoryBytes: 1 << 40, StorageBytes: 1 << 40, Slots: 100}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	storetest.Reconcile(t, s, storetest.Scope, "1")
	raw := storetest.Object(t, storetest.Start(t, "a"))
	raw["spec"].(map[string]any)["templateVersion"] = "linux-github-disk-v1"
	if _, err = s.AcceptCommand(context.Background(), storetest.Scope, storetest.Encode(t, "HostCommand", raw)); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Incomplete(context.Background(), agent.ExecutionCursor{}, 100)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	return Manager{Path: root, Store: s, Scope: storetest.Scope}, rows[0].Identity, state
}
func TestFreshStorageRetainsImmutableIdentityAndDisposalFence(t *testing.T) {
	m, id := fixture(t)
	ctx := context.Background()
	r, err := m.Prepare(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := m.Prepare(ctx, id)
	if err != nil || retry != r {
		t.Fatal("retry replaced original allocation", err)
	}
	outside := t.TempDir()
	canary := filepath.Join(outside, "keep")
	os.WriteFile(canary, []byte("keep"), 0600)
	os.Symlink(outside, filepath.Join(m.Path, r.Name, "workspace", "outside"))
	os.WriteFile(filepath.Join(m.Path, r.Name, "home", "content"), []byte("job"), 0600)
	if err = m.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if err = m.Dispose(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err = m.Dispose(ctx, id); err != nil {
		t.Fatal("idempotent disposal", err)
	}
	if _, err = os.Stat(canary); err != nil {
		t.Fatal("symlink escaped root", err)
	}
	if _, err = os.Stat(filepath.Join(m.Path, r.Name)); !os.IsNotExist(err) {
		t.Fatal("workspace retained", err)
	}
	if _, err = m.Prepare(ctx, id); err == nil {
		t.Fatal("disposed identity reused")
	}
	rows, err := m.Store.StorageRecords(ctx)
	if err != nil || len(rows) != 1 || rows[0].State != "disposed" {
		t.Fatal("fence lost", err)
	}
}
func TestUnknownAndReplacedDirectoryQuarantine(t *testing.T) {
	for _, mode := range []string{"unknown", "replaced", "missing", "unexpected-child"} {
		t.Run(mode, func(t *testing.T) {
			m, id := fixture(t)
			ctx := context.Background()
			r, err := m.Prepare(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(m.Path, r.Name)
			switch mode {
			case "unknown":
				os.Mkdir(filepath.Join(m.Path, "unknown"), 0700)
			case "replaced":
				os.Rename(path, path+"-original")
				os.Mkdir(path, 0700)
			case "missing":
				os.Rename(path, path+"-original")
			case "unexpected-child":
				os.WriteFile(filepath.Join(path, "unknown"), []byte("unknown"), 0600)
			}
			if mode == "unexpected-child" {
				err = m.Dispose(ctx, id)
			} else {
				err = m.Verify(ctx)
			}
			if !errors.Is(err, ErrQuarantined) {
				t.Fatal("uncertainty accepted", err)
			}
			r, err = m.Record(ctx, id)
			if err != nil || r.State == "disposed" {
				t.Fatal("ownership lost", r, err)
			}
		})
	}
}
func TestInterruptedRetirementResumesOriginalAndRejectsReplacement(t *testing.T) {
	m, id := fixture(t)
	ctx := context.Background()
	r, err := m.Prepare(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	retiring := r
	retiring.State = "retiring"
	if err = m.Store.StorageTransition(ctx, m.Scope, r, retiring); err != nil {
		t.Fatal(err)
	}
	// Simulate crash after filesystem deletion but before journal disposal commit.
	if err = os.RemoveAll(filepath.Join(m.Path, r.Name)); err != nil {
		t.Fatal(err)
	}
	if err = m.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if err = m.Dispose(ctx, id); err != nil {
		t.Fatal("original retirement not recovered", err)
	}
	os.Mkdir(filepath.Join(m.Path, r.Name), 0700)
	if err = m.Verify(ctx); !errors.Is(err, ErrQuarantined) {
		t.Fatal("replaced retired path accepted", err)
	}
}
func TestAmbiguousMkdirCannotBeAdopted(t *testing.T) {
	m, id := fixture(t)
	ctx := context.Background()
	fd, root, err := m.root()
	if err != nil {
		t.Fatal(err)
	}
	os.NewFile(uintptr(fd), "root").Close()
	r := journal.ExecutionStorage{Identity: id, Endpoint: m.Scope.EndpointIdentity, Root: m.Path, Name: Name(id), RootIdentity: root, State: "intent"}
	if _, err = m.Store.StorageIntent(ctx, m.Scope, r); err != nil {
		t.Fatal(err)
	}
	os.Mkdir(filepath.Join(m.Path, r.Name), 0700)
	if _, err = m.Prepare(ctx, id); !errors.Is(err, ErrQuarantined) {
		t.Fatal("unowned inode adopted", err)
	}
}
func TestHeadroomPressureDoesNotAuthorizeCleanup(t *testing.T) {
	m, id := fixture(t)
	ctx := context.Background()
	if _, err := m.Prepare(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := m.Headroom(^uint64(0)); !errors.Is(err, ErrPressure) {
		t.Fatal(err)
	}
	r, err := m.Record(ctx, id)
	if err != nil || r.State != "allocated" {
		t.Fatal("pressure changed obligation", err)
	}
}

func TestConcurrentExecutionsKeepDistinctStorage(t *testing.T) {
	m, id := fixture(t)
	ctx := context.Background()
	v := storetest.Object(t, storetest.Start(t, "b"))
	v["spec"].(map[string]any)["templateVersion"] = "linux-github-disk-v1"
	if _, err := m.Store.AcceptCommand(ctx, m.Scope, storetest.Encode(t, "HostCommand", v)); err != nil {
		t.Fatal(err)
	}
	rows, err := m.Store.Incomplete(ctx, agent.ExecutionCursor{}, 100)
	if err != nil || len(rows) != 2 {
		t.Fatal(err)
	}
	other := rows[1].Identity
	if other == id {
		other = rows[0].Identity
	}
	a, err := m.Prepare(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Prepare(ctx, other)
	if err != nil || a.Name == b.Name {
		t.Fatal("shared allocation", err)
	}
	canary := filepath.Join(m.Path, b.Name, "workspace", "keep")
	os.WriteFile(canary, []byte("second execution"), 0600)
	if err = m.Dispose(ctx, id); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(canary); err != nil || string(raw) != "second execution" {
		t.Fatal("cross execution deletion", err)
	}
	if err = m.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestPermissionFailureRetainsRetirement(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission denial must run nonroot")
	}
	m, id := fixture(t)
	ctx := context.Background()
	r, err := m.Prepare(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.Path, r.Name, "workspace", "restricted")
	os.Mkdir(path, 0700)
	os.WriteFile(filepath.Join(path, "keep"), []byte("protected"), 0600)
	os.Chmod(path, 0000)
	defer os.Chmod(path, 0700)
	if err = m.Dispose(ctx, id); !errors.Is(err, ErrQuarantined) {
		t.Fatal("permission failure claimed disposal", err)
	}
	r, err = m.Record(ctx, id)
	if err != nil || r.State != "retiring" {
		t.Fatal("retirement lost", err)
	}
	os.Chmod(path, 0700)
	if err = m.Dispose(ctx, id); err != nil {
		t.Fatal("authorized retry not recovered", err)
	}
}
func TestProcessRestartRetainsOriginalStorage(t *testing.T) {
	m, id, state := fixtureAt(t)
	ctx := context.Background()
	r, err := m.Prepare(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(m.Path, r.Name, "workspace", "keep")
	os.WriteFile(canary, []byte("original"), 0600)
	if err = m.Store.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := journal.OpenRecovery(ctx, state, journal.Options{ReservationLimits: agent.ReservationLimits{CPUMillis: 100000, MemoryBytes: 1 << 40, StorageBytes: 1 << 40, Slots: 100}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m.Store = s
	storetest.Reconcile(t, s, m.Scope, "2", agent.Watermark{ExecutionID: id.ExecutionID, Generation: id.Generation, ContiguousSequence: "0"})
	if err = m.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	retry, err := m.Prepare(ctx, id)
	if err != nil || retry != r {
		t.Fatal("restart allocated replacement", err)
	}
	if b, err := os.ReadFile(canary); err != nil || string(b) != "original" {
		t.Fatal("original state lost", err)
	}
	if err = m.Dispose(ctx, id); err != nil {
		t.Fatal(err)
	}
}

func TestUnmaterializedIntentCanRetireButAmbiguousDirectoryCannot(t *testing.T) {
	for _, exists := range []bool{false, true} {
		t.Run(fmt.Sprint(exists), func(t *testing.T) {
			m, id := fixture(t)
			ctx := context.Background()
			fd, root, err := m.root()
			if err != nil {
				t.Fatal(err)
			}
			os.NewFile(uintptr(fd), "root").Close()
			r := journal.ExecutionStorage{Identity: id, Endpoint: m.Scope.EndpointIdentity, Root: m.Path, Name: Name(id), RootIdentity: root, State: "intent"}
			if _, err = m.Store.StorageIntent(ctx, m.Scope, r); err != nil {
				t.Fatal(err)
			}
			if exists {
				os.Mkdir(filepath.Join(m.Path, r.Name), 0700)
			}
			err = m.Dispose(ctx, id)
			if exists {
				if !errors.Is(err, ErrQuarantined) {
					t.Fatal("ambiguous intent retired", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				r, err = m.Record(ctx, id)
				if err != nil || r.State != "disposed" {
					t.Fatal("unmaterialized obligation lost", err)
				}
			}
		})
	}
}
