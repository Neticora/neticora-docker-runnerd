//go:build linux

package katalinux

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestStandaloneNativeSandboxAbsence(t *testing.T) {
	if os.Geteuid() != 0 {
		if os.Getenv("RUNNERD09_REQUIRE_NATIVE_TESTS") == "1" {
			t.Fatal("native teardown check requires root")
		}
		t.Skip("requires root ownership of the native runtime tree")
	}
	anchor := t.TempDir()
	if err := os.Chmod(anchor, 0700); err != nil {
		t.Fatal(err)
	}
	sandboxes := filepath.Join(anchor, "sandboxes")
	if err := os.Mkdir(sandboxes, 0700); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 64)
	foreign := strings.Repeat("b", 64)
	var info syscall.Stat_t
	if err := syscall.Stat(anchor, &info); err != nil {
		t.Fatal(err)
	}
	check := func(path string, device uint64) error {
		return verifyNativeSandboxAbsence(anchor, []string{path}, id, device)
	}
	t.Run("retains-runtime-residue", func(t *testing.T) {
		entry := filepath.Join(sandboxes, id)
		if err := os.WriteFile(entry, []byte("owned"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := check(sandboxes, uint64(info.Dev)); err == nil {
			t.Fatal("accepted existing metadata")
		}
		if data, err := os.ReadFile(entry); err != nil || string(data) != "owned" {
			t.Fatal("reconciliation changed runtime metadata", err)
		}
		if err := os.Remove(entry); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("rejects-replaced-parent", func(t *testing.T) {
		alias := filepath.Join(anchor, "alias")
		if err := os.Symlink(sandboxes, alias); err != nil {
			t.Fatal(err)
		}
		if err := check(alias, uint64(info.Dev)); err == nil {
			t.Fatal("accepted alias for the signed root")
		}
		if err := check(sandboxes, uint64(info.Dev)^1); err == nil {
			t.Fatal("accepted unqualified filesystem")
		}
	})
	t.Run("accepts-exact-absence", func(t *testing.T) {
		if err := os.Mkdir(filepath.Join(sandboxes, foreign), 0700); err != nil {
			t.Fatal(err)
		}
		if err := check(sandboxes, uint64(info.Dev)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(sandboxes, foreign)); err != nil {
			t.Fatal("changed another execution's metadata", err)
		}
	})
}
