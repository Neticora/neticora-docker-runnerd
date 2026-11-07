//go:build linux

package katalinux

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Ordinary developer runs may skip unavailable native prerequisites. The
// dedicated qualification gate requires every case to execute successfully.
func nativeUnavailable(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("RUNNERD09_REQUIRE_NATIVE_TESTS") == "1" {
		t.Fatal(reason)
	}
	t.Skip(reason)
}

func startSurvivingWorker(t *testing.T, mode, target string) (string, string) {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		nativeUnavailable(t, "C compiler required for actual pthread_exit regression")
	}
	binary := filepath.Join(t.TempDir(), "worker")
	if raw, err := exec.Command(cc, "-Wall", "-Wextra", "-Werror", "-pthread", "testdata/surviving_worker.c", "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile worker: %v: %s", err, raw)
	}
	cmd := exec.Command(binary, mode, target)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("worker did not exit")
		}
	})
	line := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(out)
		if scanner.Scan() {
			line <- scanner.Text()
		} else {
			line <- ""
		}
	}()
	select {
	case ready := <-line:
		var tid int
		if _, err := fmt.Sscanf(ready, "READY %d", &tid); err != nil {
			select {
			case err := <-done:
				done <- err
				if mode == "namespace" {
					if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 77 {
						nativeUnavailable(t, "kernel/sandbox disallows disposable user/mount namespaces")
					}
				}
				t.Fatalf("worker failed: %v", err)
			case <-time.After(time.Second):
				t.Fatalf("worker returned no readiness: %q", ready)
			}
		}
		return strconv.Itoa(cmd.Process.Pid), strconv.Itoa(tid)
	case <-time.After(10 * time.Second):
		t.Fatal("worker readiness timeout")
	}
	return "", ""
}
func TestSurvivingWorkerRetainsMmapAfterFDClosure(t *testing.T) {
	for _, unlink := range []bool{false, true} {
		t.Run(fmt.Sprintf("unlinked=%v", unlink), func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "execution.raw")
			if err := os.WriteFile(file, make([]byte, 4096), 0600); err != nil {
				t.Fatal(err)
			}
			var st syscall.Stat_t
			if err := syscall.Stat(file, &st); err != nil {
				t.Fatal(err)
			}
			pid, tid := startSurvivingWorker(t, "mmap", file)
			task := filepath.Join("/proc", pid, "task", tid)
			fds, err := os.ReadDir(filepath.Join(task, "fd"))
			if err != nil {
				t.Fatal(err)
			}
			for _, fd := range fds {
				var opened syscall.Stat_t
				if syscall.Stat(filepath.Join(task, "fd", fd.Name()), &opened) == nil && opened.Ino == st.Ino && opened.Dev == st.Dev {
					t.Fatal("fixture still holds an FD; mmap-only condition not established")
				}
			}
			if unlink {
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			}
			r := BlockRecord{FileDevice: uint64(st.Dev), FileInode: st.Ino}
			if err := noTaskBlockUsers(context.Background(), task, r); !errors.Is(err, ErrQualification) {
				t.Fatalf("live mapped reference accepted: %v", err)
			}
			if _, err := readProcessTasks(context.Background(), pid); err != nil && !errors.Is(err, ErrQualification) {
				t.Fatal(err)
			}
			// Exercise the full scanner on a proc tree containing only this real worker.
			root := t.TempDir()
			base := filepath.Join(root, pid, "task")
			if err := os.MkdirAll(base, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(task, filepath.Join(base, tid)); err != nil {
				t.Fatal(err)
			}
			if err := noBlockUsersIn(context.Background(), root, r); !errors.Is(err, ErrQualification) {
				t.Fatalf("worker mapping lost by scanner: %v", err)
			}
		})
	}
}
func TestSurvivingWorkerRetainsIndependentMountNamespace(t *testing.T) {
	target := t.TempDir()
	pid, tid := startSurvivingWorker(t, "namespace", target)
	task := filepath.Join("/proc", pid, "task", tid)
	raw, err := os.ReadFile(filepath.Join(task, "mountinfo"))
	if err != nil {
		t.Fatal(err)
	}
	var dev uint64
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 5 && fields[4] == target {
			var major, minor uint64
			if _, err := fmt.Sscanf(fields[2], "%d:%d", &major, &minor); err != nil {
				t.Fatal(err)
			}
			dev = uint64((minor & 0xff) | ((major & 0xfff) << 8) | ((minor &^ 0xff) << 12))
			found = true
		}
	}
	if !found {
		t.Fatal("worker's private tmpfs mount missing")
	}
	own, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	worker, err := os.Readlink(filepath.Join(task, "ns/mnt"))
	if err != nil {
		t.Fatal(err)
	}
	if own == worker {
		t.Fatal("worker shares observer mount namespace")
	}
	root := t.TempDir()
	base := filepath.Join(root, pid, "task")
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(task, filepath.Join(base, tid)); err != nil {
		t.Fatal(err)
	}
	if err := loopMountedIn(context.Background(), root, dev); !errors.Is(err, ErrQualification) {
		t.Fatalf("worker's independent mount accepted: %v", err)
	}
}
