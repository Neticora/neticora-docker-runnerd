//go:build linux

package hostfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedFilesAndLock(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "secret")
	if err := os.WriteFile(file, []byte("token"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := ReadPrivate(file, 5)
	if err != nil || string(data) != "token" {
		t.Fatal(err)
	}
	if _, err = ReadPrivate(file, 4); err == nil {
		t.Fatal("oversized file accepted")
	}
	if err = os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPrivate(file, 5); err == nil {
		t.Fatal("world-readable identity accepted")
	}
	link := filepath.Join(dir, "link")
	if err = os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPrivate(link, 5); err == nil {
		t.Fatal("symlink identity accepted")
	}
	parentLink := filepath.Join(dir, "directory-link")
	if err = os.Symlink(dir, parentLink); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPrivate(filepath.Join(parentLink, "secret"), 5); err == nil {
		t.Fatal("symlink ancestor accepted")
	}

	root, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	first, err := Lock(root)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := Lock(root); err == nil {
		second.Close()
		t.Fatal("second owner accepted")
	}
	first.Close()
	again, err := Lock(root)
	if err != nil {
		t.Fatal(err)
	}
	again.Close()
	if _, err = os.Stat(filepath.Join(dir, "instance.lock")); err != nil {
		t.Fatal("lock inode removed")
	}
}
func TestStateDoesNotRepairUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	unsafe := filepath.Join(dir, "unsafe")
	if err := os.Mkdir(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(unsafe, 0777)
	if root, err := OpenState(unsafe); err == nil {
		root.Close()
		t.Fatal("unsafe state accepted")
	}
	link := filepath.Join(dir, "alias")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if root, err := OpenState(link); err == nil {
		root.Close()
		t.Fatal("symlink state accepted")
	}
	if _, err := OpenState(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("missing state silently created")
	}
}
