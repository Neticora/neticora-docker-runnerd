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
	for _, kind := range []string{"regular", "directory", "opath"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC
			if kind == "opath" {
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
			cmd.Env = append(os.Environ(), "RUNNERD09_ENTRY_FD_CHILD=1")
			cmd.ExtraFiles = []*os.File{file}
			output, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(output), "inherited descriptor 3 rejected") {
				t.Fatalf("entry guard failed: %v %s", err, output)
			}
		})
	}
}
func TestBrokerEntryDescriptorChild(t *testing.T) {
	if os.Getenv("RUNNERD09_ENTRY_FD_CHILD") != "1" {
		t.Skip("subprocess only")
	}
	err := CheckBrokerEntryDescriptors()
	if err == nil || !strings.Contains(err.Error(), "inherited descriptor 3") {
		t.Fatal("privileged inherited resource accepted", err)
	}
	t.Log("inherited descriptor 3 rejected")
}
