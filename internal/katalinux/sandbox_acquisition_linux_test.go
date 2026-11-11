//go:build linux

package katalinux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNativeSandboxReferenceTypesFromSurvivingThread(t *testing.T) {
	for _, mode := range []string{"fd", "opath", "dir", "cwd", "root", "mmap", "namespace-hidden-bind"} {
		t.Run(mode, func(t *testing.T) {
			p, directory, id, stamp := sandboxNative(t)
			target := filepath.Join(directory, id, "rw", "hosts")
			if mode == "dir" || mode == "cwd" || mode == "root" || mode == "namespace-hidden-bind" {
				target = filepath.Join(directory, id, "rw")
			}
			startSurvivingWorker(t, mode, target)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			if mode == "root" {
				var st syscall.Stat_t
				if err := syscall.Stat(target, &st); err != nil {
					t.Fatal(err)
				}
				path, err := sandboxFilesystemPath(target, uint64(st.Dev))
				if err != nil {
					t.Fatal(err)
				}
				if err = noSandboxNamespaceReferences(ctx, uint64(st.Dev), st.Ino, path); !errors.Is(err, errSandboxReferenceHeld) {
					t.Fatal("process root reference not identified", err)
				}
			}
			err := p.removeSandboxResidue(ctx, id, []SandboxDirectory{stamp}, func() error { return nil })
			// Chroot can make unrelated mountpoints unresolvable when checking a
			// child inode. That uncertainty must retain the tree; the positive root
			// predicate itself is independently required above.
			if !errors.Is(err, errSandboxReferenceHeld) && !(mode == "root" && errors.Is(err, ErrQualification)) {
				t.Fatal("reference was not the rejection cause", err)
			}
			if _, err = os.Stat(target); err != nil {
				t.Fatal("held reference removed", err)
			}
		})
	}
}

func TestNativeSandboxReferenceAcquiredDuringMapsRead(t *testing.T) {
	for _, mode := range []string{"fd", "opath", "mmap"} {
		t.Run(mode, func(t *testing.T) {
			_, directory, id, _ := sandboxNative(t)
			target := filepath.Join(directory, id, "rw", "hosts")
			if err := os.Truncate(target, 4096); err != nil {
				t.Fatal(err)
			}
			var st syscall.Stat_t
			if err := syscall.Stat(target, &st); err != nil {
				t.Fatal(err)
			}
			proc := t.TempDir()
			task := filepath.Join(proc, "42", "task", "42")
			if err := os.MkdirAll(task, 0700); err != nil {
				t.Fatal(err)
			}
			fifo := filepath.Join(task, "maps")
			if err := unix.Mkfifo(fifo, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/proc/self/fd", filepath.Join(task, "fd")); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			ctx = context.WithValue(ctx, procDecodeKey{}, &procDecoder{})
			done := make(chan error, 1)
			var held int = -1
			var mapping []byte
			go func() {
				writer, err := os.OpenFile(fifo, os.O_WRONLY, 0600)
				if err != nil {
					done <- err
					return
				}
				defer writer.Close()
				// The scanner has opened and blocked on maps before acquisition.
				flags := unix.O_RDONLY
				if mode == "opath" {
					flags = unix.O_PATH
				}
				held, err = unix.Open(target, flags, 0)
				if err == nil && mode == "mmap" {
					mapping, err = unix.Mmap(held, 0, 4096, unix.PROT_READ, unix.MAP_SHARED)
					unix.Close(held)
					held = -1
				}
				if err == nil {
					var raw []byte
					raw, err = os.ReadFile("/proc/self/maps")
					if err == nil {
						_, err = writer.Write(raw)
					}
				}
				done <- err
			}()
			err := noBlockUsersIn(ctx, proc, BlockRecord{FileDevice: uint64(st.Dev), FileInode: st.Ino})
			if writerErr := <-done; writerErr != nil {
				t.Fatal(writerErr)
			}
			defer func() {
				if held >= 0 {
					unix.Close(held)
				}
				if mapping != nil {
					unix.Munmap(mapping)
				}
			}()
			if !errors.Is(err, errSandboxReferenceHeld) {
				t.Fatal("new current reference missed during scan", err)
			}
			if _, err = os.Stat(target); err != nil {
				t.Fatal("protected inode changed", err)
			}
		})
	}
}

func TestProcReadBuffersDoNotReuseObservationBytes(t *testing.T) {
	file := filepath.Join(t.TempDir(), "metadata")
	ctx := context.WithValue(t.Context(), procDecodeKey{}, &procDecoder{})
	for _, text := range []string{strings.Repeat("a", 40000), "short", ""} {
		if err := os.WriteFile(file, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		raw, release, err := readProcCurrent(ctx, file, 0)
		if err != nil || string(raw) != text {
			t.Fatal("old read-buffer contents reused", err, len(raw))
		}
		release()
	}
}
