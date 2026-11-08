//go:build linux

package katalinux

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func settleSandboxTest(t *testing.T, operation func() error) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := operation()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("same-scope cleanup/observation remains fenced:", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func sandboxNative(t *testing.T) (*Profile, string, string, SandboxDirectory) {
	t.Helper()
	if os.Geteuid() != 0 {
		nativeUnavailable(t, "root-owned sandbox runtime fixture requires native root qualification")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 64)
	if err := os.MkdirAll(filepath.Join(root, id, "rw"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id, "rw", "hosts"), []byte("owned runtime residue"), 0600); err != nil {
		t.Fatal(err)
	}
	stamp, err := sandboxStamp(root, root, id)
	if err != nil {
		t.Fatal(err)
	}
	p := &Profile{Manifest: Manifest{Version: MultiBlockVersion, SandboxRoots: []string{root}}}
	p.Manifest.Storage.Runtime.Root = root
	p.Manifest.Storage.Runtime.Device = stamp.Device
	return p, root, id, stamp
}

func TestSandboxRejectsUnconfinedIdentity(t *testing.T) {
	for _, id := range []string{"", "../foreign", strings.Repeat("/", 64), strings.Repeat("z", 64)} {
		root := t.TempDir()
		if _, err := sandboxStamp(root, root, id); err == nil {
			t.Fatal("unconfined runtime identity accepted")
		}
	}
}

func TestNativeSandboxResidueCleanup(t *testing.T) {
	p, root, id, stamp := sandboxNative(t)
	peer := filepath.Join(root, strings.Repeat("b", 64))
	if err := os.Mkdir(peer, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(peer, "keep"), []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	settleSandboxTest(t, func() error {
		return p.removeSandboxResidue(context.Background(), id, []SandboxDirectory{stamp}, func() error { return nil })
	})
	if _, err := os.Stat(filepath.Join(root, id)); !os.IsNotExist(err) {
		t.Fatal("captured runtime residue remains")
	}
	if raw, err := os.ReadFile(filepath.Join(peer, "keep")); err != nil || string(raw) != "unrelated" {
		t.Fatal("peer changed")
	}
}

func TestNativeSandboxHeldReferenceRetainsOwnership(t *testing.T) {
	p, root, id, stamp := sandboxNative(t)
	f, err := os.Open(filepath.Join(root, id, "rw", "hosts"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := p.removeSandboxResidue(context.Background(), id, []SandboxDirectory{stamp}, func() error { return nil }); err == nil {
		t.Fatal("held runtime inode deleted")
	}
	f.Close()
	settleSandboxTest(t, func() error {
		return p.removeSandboxResidue(context.Background(), id, []SandboxDirectory{stamp}, func() error { return nil })
	})
}

func TestNativeSandboxReplacementAndGuardRejectDeletion(t *testing.T) {
	p, root, id, stamp := sandboxNative(t)
	if err := p.removeSandboxResidue(context.Background(), id, []SandboxDirectory{stamp}, func() error { return ErrQualification }); err == nil {
		t.Fatal("uncertain runtime guard ignored")
	}
	if err := os.Rename(filepath.Join(root, id), filepath.Join(root, "retained-original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, id), 0700); err != nil {
		t.Fatal(err)
	}
	if err := p.removeSandboxResidue(context.Background(), id, []SandboxDirectory{stamp}, func() error { return nil }); err == nil {
		t.Fatal("replacement directory adopted from name alone")
	}
	if _, err := os.Stat(filepath.Join(root, id)); err != nil {
		t.Fatal("replacement directory changed")
	}
}

func TestNativeSandboxUnlinkedDirectoryRetainsReference(t *testing.T) {
	p, root, id, stamp := sandboxNative(t)
	f, err := os.Open(filepath.Join(root, id))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.RemoveAll(filepath.Join(root, id)); err != nil {
		t.Fatal(err)
	}
	if err := p.removeSandboxResidue(context.Background(), id, []SandboxDirectory{stamp}, func() error { return nil }); err == nil {
		t.Fatal("unlinked directory with live reference counted absent")
	}
	f.Close()
	settleSandboxTest(t, func() error {
		return p.removeSandboxResidue(context.Background(), id, []SandboxDirectory{stamp}, func() error { return nil })
	})
}

func TestNativeSandboxForeignEntriesRemainFenced(t *testing.T) {
	for _, mode := range []string{"symlink", "foreign-owner", "writable"} {
		t.Run(mode, func(t *testing.T) {
			p, root, id, stamp := sandboxNative(t)
			path := filepath.Join(root, id, "rw", "hosts")
			switch mode {
			case "symlink":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/etc/passwd", path); err != nil {
					t.Fatal(err)
				}
			case "foreign-owner":
				if err := os.Chown(path, 10001, 10001); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.removeSandboxResidue(context.Background(), id, []SandboxDirectory{stamp}, func() error { return nil }); err == nil {
				t.Fatal("untrusted runtime entry deleted")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("untrusted runtime entry changed")
			}
		})
	}
}

func TestNativeSandboxPrivateAnchorControlsRuntimeModes(t *testing.T) {
	p, root, id, _ := sandboxNative(t)
	shared := filepath.Join(root, "shared")
	if err := os.Mkdir(shared, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, id), filepath.Join(shared, id)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(shared, id), 0777); err != nil {
		t.Fatal(err)
	}
	p.Manifest.SandboxRoots = []string{shared, filepath.Join(root, "unused", "missing")}
	directories, err := p.captureSandboxDirectories(id)
	if err != nil || len(directories) != 1 {
		t.Fatal("private runtime-created layout rejected:", err)
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := p.removeSandboxResidue(context.Background(), id, directories, func() error { return nil }); err == nil {
		t.Fatal("non-private filesystem anchor accepted")
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	settleSandboxTest(t, func() error {
		return p.removeSandboxResidue(context.Background(), id, directories, func() error { return nil })
	})
}

func TestNativeSandboxCwdRetainsDirectory(t *testing.T) {
	_, root, id, _ := sandboxNative(t)
	path := filepath.Join(root, id)
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	// A separate process is unnecessary: the observer must also notice its own
	// cwd reference, rather than treating its process as exempt from inspection.
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(path); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err := noSandboxNamespaceReferences(context.Background(), uint64(st.Dev), st.Ino, ""); err == nil {
		t.Fatal("live cwd reference ignored")
	}
}

func TestNativeSandboxHiddenWorkerMountRetainsDirectory(t *testing.T) {
	_, root, id, stamp := sandboxNative(t)
	path := filepath.Join(root, id)
	filesystemPath, err := sandboxFilesystemPath(path, stamp.Device)
	if err != nil {
		t.Fatal("baseline namespace inspection unavailable:", err)
	}
	settleSandboxTest(t, func() error {
		return noSandboxNamespaceReferences(context.Background(), stamp.Device, stamp.Inode, filesystemPath)
	})
	pid, tid := startSurvivingWorker(t, "namespace-hidden-bind", path)
	raw, err := os.ReadFile(filepath.Join("/proc", pid, "task", tid, "mountinfo"))
	if err != nil {
		t.Fatal(err)
	}
	count, matched := 0, false
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || decodeSandboxMountPath(fields[4]) != path {
			continue
		}
		count++
		device, err := sandboxMountDevice(fields[2])
		if err == nil && device == stamp.Device && decodeSandboxMountPath(fields[3]) == filesystemPath {
			matched = true
		}
	}
	if count < 2 || !matched {
		t.Fatal("hidden bind reference was not independently established")
	}
	if err := noSandboxNamespaceReferences(context.Background(), stamp.Device, stamp.Inode, filesystemPath); err == nil {
		t.Fatal("overmounted worker namespace reference ignored")
	}
}
