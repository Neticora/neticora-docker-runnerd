//go:build linux

package journal

import (
	"context"
	"errors"
	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"strings"
	"testing"
)

func TestDiskCleanupCannotReleaseReservationBeforeStorageDisposed(t *testing.T) {
	ctx := context.Background()
	s := recovery(t, privateDir(t), Options{})
	storetest.Reconcile(t, s, storetest.Scope, "1")
	v := storetest.Object(t, storetest.Start(t, "disk"))
	v["spec"].(map[string]any)["templateVersion"] = "linux-github-disk-v1"
	start := storetest.Encode(t, "HostCommand", v)
	if _, err := s.AcceptCommand(ctx, storetest.Scope, start); err != nil {
		t.Fatal(err)
	}
	for seq, state := range []string{"exited", "cleanup-pending"} {
		event := storetest.Event(t, start, uint64(seq+1), state)
		var err error
		if seq == 0 {
			err = s.RecordObservation(ctx, storetest.Scope, event)
		} else {
			err = s.RequireCleanup(ctx, storetest.Scope, event)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	cleaned := storetest.Event(t, start, 3, "cleaned")
	proof := storetest.Proof(t, cleaned, "1")
	assertBlocked := func() {
		t.Helper()
		if err := s.CompleteCleanup(ctx, storetest.Scope, cleaned, proof); !errors.Is(err, agent.ErrRecoveryRequired) {
			t.Fatal("storage bypass", err)
		}
		var released bool
		if err := s.db.QueryRow("SELECT released FROM reservations").Scan(&released); err != nil || released {
			t.Fatal("reservation released", err)
		}
	}
	assertBlocked()
	rows, err := s.Incomplete(ctx, agent.ExecutionCursor{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	r := ExecutionStorage{Identity: rows[0].Identity, Endpoint: storetest.Scope.EndpointIdentity, Root: "/mnt/executions", Name: "nrd-" + strings.Repeat("a", 64), RootIdentity: StorageIdentity{Device: 1, Inode: 2}, State: "intent"}
	r, err = s.StorageIntent(ctx, storetest.Scope, r)
	if err != nil {
		t.Fatal(err)
	}
	assertBlocked()
	for _, state := range []string{"allocated", "retiring", "disposed"} {
		next := r
		next.State = state
		if state == "allocated" {
			next.DirectoryIdentity = StorageIdentity{Device: 1, Inode: 4}
		}
		if err = s.StorageTransition(ctx, storetest.Scope, r, next); err != nil {
			t.Fatal(err)
		}
		r = next
		if state != "disposed" {
			assertBlocked()
		}
	}
	if err = s.CompleteCleanup(ctx, storetest.Scope, cleaned, proof); err != nil {
		t.Fatal("verified storage blocked", err)
	}
	var released bool
	if err = s.db.QueryRow("SELECT released FROM reservations").Scan(&released); err != nil || !released {
		t.Fatal("reservation lifecycle failed", err)
	}
	changed := r
	changed.State = "allocated"
	if err = s.StorageTransition(ctx, storetest.Scope, r, changed); !errors.Is(err, agent.ErrConflict) {
		t.Fatal("disposed fence reset", err)
	}
}
