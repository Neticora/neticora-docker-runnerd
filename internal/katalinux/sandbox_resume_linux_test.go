//go:build linux

package katalinux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeSandboxCleanupBudgetIsResumable(t *testing.T) {
	p, directory, id, stamp := sandboxNative(t)
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(filepath.Join(directory, id, "rw", fmt.Sprint(i)), []byte("owned"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	left := 4
	err = removeSandboxTree(t.Context(), root, id, stamp.Device, stamp.Inode, 0, &left, func() error { return nil })
	root.Close()
	if !errors.Is(err, errSandboxCleanupPending) {
		t.Fatal("partial request claimed completion or rejected resumable budget", err)
	}
	remaining, err := os.ReadDir(filepath.Join(directory, id, "rw"))
	if err != nil || len(remaining) != 4 {
		t.Fatal("durable prefix did not remove exactly two entries", len(remaining), err)
	}
	// A new invocation has no trusted snapshot/cursor or negative reference cache.
	// A reference acquired after interruption must fence the next cleanup.
	held := filepath.Join(directory, id, "rw", remaining[0].Name())
	f, err := os.Open(held)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = p.removeSandboxResidue(t.Context(), id, []SandboxDirectory{stamp}, func() error { return nil }); err == nil {
		t.Fatal("retry ignored newly acquired reference")
	}
	if _, err = os.Stat(held); err != nil {
		t.Fatal("held inode was removed on retry", err)
	}
	f.Close()
	settleSandboxTest(t, func() error {
		return p.removeSandboxResidue(t.Context(), id, []SandboxDirectory{stamp}, func() error { return nil })
	})
	if _, err = os.Stat(filepath.Join(directory, id)); !os.IsNotExist(err) {
		t.Fatal("same captured directory did not finish", err)
	}
}

func TestNativeSandboxLargeDirectoryUsesRequestBudget(t *testing.T) {
	_, directory, id, stamp := sandboxNative(t)
	// This is a wide single directory, beyond the old deterministic 4096-child
	// rejection. Budget one must yield retryable progress, not a lifetime limit.
	for i := 0; i < 4100; i++ {
		if err := os.WriteFile(filepath.Join(directory, id, fmt.Sprintf("wide-%04d", i)), []byte("owned"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	left := 1
	metrics := &sandboxMetrics{}
	ctx := context.WithValue(t.Context(), sandboxMetricsKey{}, metrics)
	err = removeSandboxTree(ctx, root, id, stamp.Device, stamp.Inode, 0, &left, func() error { t.Fatal("no entry budget left for deletion"); return nil })
	if !errors.Is(err, errSandboxCleanupPending) {
		t.Fatal("wide directory permanently fenced instead of bounded retry", err)
	}
	entries, err := os.ReadDir(filepath.Join(directory, id))
	if err != nil || len(entries) != 4101 {
		t.Fatal("budget-only inventory changed directory", err, len(entries))
	}
}
