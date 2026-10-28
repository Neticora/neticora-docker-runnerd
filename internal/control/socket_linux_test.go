//go:build linux

package control

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func privateSocketPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "control.sock")
}
func TestOwnedSocketCleanupAndRepeatedClose(t *testing.T) {
	path := privateSocketPath(t)
	listener, err := listenSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("owned socket remained after close")
	}
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := listenSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = again.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestCleanupPreservesReplacedPaths(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "socket"} {
		t.Run(kind, func(t *testing.T) {
			path := privateSocketPath(t)
			listener, err := listenSocket(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			// Retain the original inode under another name to prevent inode-number reuse.
			original := path + ".original"
			if err = os.Rename(path, original); err != nil {
				t.Fatal(err)
			}
			var replacement *net.UnixListener
			switch kind {
			case "file":
				err = os.WriteFile(path, []byte("preserve"), 0600)
			case "symlink":
				err = os.Symlink(original, path)
			case "socket":
				replacement, err = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
				if err == nil {
					replacement.SetUnlinkOnClose(false)
					t.Cleanup(func() { _ = replacement.Close() })
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = listener.Close(); err == nil {
				t.Fatal("replacement identity was not reported")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("replacement was deleted or changed")
			}
			if _, err = os.Lstat(original); err != nil {
				t.Fatal("renamed original was deleted")
			}
		})
	}
}
func TestShutdownBeforeServeRemovesOwnedSocket(t *testing.T) {
	path := privateSocketPath(t)
	server, err := Listen(path, func() Snapshot { return Snapshot{} }, func() {}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("bound but unserved socket leaked")
	}
	if err = server.Serve(); err != nil {
		t.Fatal(err)
	}
}
func TestStaleSocketRequiresExplicitInspection(t *testing.T) {
	path := privateSocketPath(t)
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	_ = stale.Close()
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if listener, err := listenSocket(path); err == nil {
		_ = listener.Close()
		t.Fatal("stale socket adopted or replaced")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("stale socket changed")
	}
}
