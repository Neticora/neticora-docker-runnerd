//go:build linux

package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDrainFenceIsPrivatePersistentAndNeverFollowsSymlinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "admission.drained")
	if err := persistDrain(path); err != nil {
		t.Fatal(err)
	}
	first, err := os.Stat(path)
	if err != nil || first.Mode().Perm() != 0600 {
		t.Fatal("unsafe drain fence", err)
	}
	if err = persistDrain(path); err != nil {
		t.Fatal(err)
	}
	second, _ := os.Stat(path)
	if !os.SameFile(first, second) {
		t.Fatal("drain inode replaced")
	}
	link := filepath.Join(dir, "linked-drain")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err = persistDrain(link); err == nil {
		t.Fatal("symlinked drain state accepted")
	}
}
