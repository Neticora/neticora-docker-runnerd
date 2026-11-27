//go:build linux

package katalinux

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestObserverSocketRecoversOnlyClosedOwnedListener(t *testing.T) {
	for _, state := range []string{"absent", "stale", "live", "foreign-owner", "canceled", "regular", "symlink"} {
		t.Run(state, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "observer.sock")
			ctx, uid := t.Context(), os.Geteuid()
			if state == "regular" || state == "symlink" {
				file := path
				if state == "symlink" {
					file += ".foreign"
				}
				if err := os.WriteFile(file, []byte("preserve foreign content"), 0600); err != nil {
					t.Fatal(err)
				}
				if state == "symlink" {
					if err := os.Symlink(file, path); err != nil {
						t.Fatal(err)
					}
				}
				t.Cleanup(func() {
					if raw, err := os.ReadFile(file); err != nil || string(raw) != "preserve foreign content" {
						t.Error("foreign file changed")
					}
				})
			} else if state != "absent" {
				listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				listener.SetUnlinkOnClose(false)
				t.Cleanup(func() { listener.Close() })
				if err = os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
				if state != "live" {
					listener.Close()
				}
				if state == "foreign-owner" {
					uid++
				}
				if state == "canceled" {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
			}
			err := removeStaleObserverSocket(ctx, path, uid)
			allowed := state == "absent" || state == "stale"
			if (err == nil) != allowed {
				t.Fatalf("unexpected recovery result for %s: %v", state, err)
			}
			_, statErr := os.Lstat(path)
			if allowed && !os.IsNotExist(statErr) {
				t.Fatal("stale socket remains")
			}
			if !allowed && statErr != nil {
				t.Fatal("foreign or live listener removed")
			}
		})
	}
}
