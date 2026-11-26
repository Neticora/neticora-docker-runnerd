//go:build linux

package execution

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBrokerEntryRejectsInheritedResourceDescriptors(t *testing.T) {
	for _, kind := range []string{"regular", "directory", "opath", "opath-stdin"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC
			if strings.HasPrefix(kind, "opath") {
				flags = unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC
			}
			if kind == "regular" {
				path = filepath.Join(path, "metadata")
				if err := os.WriteFile(path, []byte("protected fixture"), 0600); err != nil {
					t.Fatal(err)
				}
				flags = unix.O_RDONLY | unix.O_CLOEXEC
			}
			fd, err := unix.Open(path, flags, 0)
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(fd), "resource-fixture")
			defer file.Close()
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(binary, "-test.run=^TestBrokerEntryDescriptorChild$", "-test.v")
			expected := "inherited descriptor 3"
			if kind == "opath-stdin" {
				cmd.Stdin = file
				expected = "privileged standard descriptor 0"
			} else {
				cmd.ExtraFiles = []*os.File{file}
			}
			cmd.Env = append(os.Environ(), "RUNNERD09_ENTRY_FD_CHILD=1", "RUNNERD09_ENTRY_FD_EXPECT="+expected)
			output, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(output), expected+" rejected") {
				t.Fatalf("entry guard failed: %v %s", err, output)
			}
		})
	}
}
func TestBrokerEntryDescriptorChild(t *testing.T) {
	if os.Getenv("RUNNERD09_ENTRY_FD_CHILD") != "1" {
		t.Skip("subprocess only")
	}
	expected := os.Getenv("RUNNERD09_ENTRY_FD_EXPECT")
	// The hosted test runner can pass unrelated descriptors into this child.
	// Preserve the injected descriptor and isolate it from the harness's files.
	if err := unix.CloseRange(4, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	err := CheckBrokerEntryDescriptors()
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatal("privileged inherited resource accepted", err)
	}
	t.Log(expected + " rejected")
}
