//go:build linux

package katalinux

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

type procFaultFS struct {
	fs.FS
	read func(string) ([]fs.DirEntry, error)
	stat func(string) (fs.FileInfo, error)
}

func (f procFaultFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if f.read != nil {
		return f.read(name)
	}
	return fs.ReadDir(f.FS, name)
}
func (f procFaultFS) Stat(name string) (fs.FileInfo, error) {
	if f.stat != nil {
		return f.stat(name)
	}
	return fs.Stat(f.FS, name)
}
func TestProcessTasksFailClosed(t *testing.T) {
	directory := &fstest.MapFile{Mode: fs.ModeDir | 0700}
	for _, tc := range []struct {
		name    string
		tree    fstest.MapFS
		wantErr bool
		workers int
	}{
		{"workers", fstest.MapFS{"42/task/43": directory}, false, 1},
		{"missing task directory", fstest.MapFS{"42": directory}, true, 0},
		{"empty task directory", fstest.MapFS{"42/task": directory}, true, 0},
		{"task path is a file", fstest.MapFS{"42/task": {}}, true, 0},
		{"group disappeared", fstest.MapFS{}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tasks, err := readProcessTasksIn(context.Background(), tc.tree, "42")
			if errors.Is(err, ErrQualification) != tc.wantErr || len(tasks) != tc.workers {
				t.Fatalf("tasks=%d error=%v", len(tasks), err)
			}
		})
	}
	for _, fault := range []error{fs.ErrPermission, errors.New("unexpected filesystem failure")} {
		t.Run(fault.Error(), func(t *testing.T) {
			source := procFaultFS{FS: fstest.MapFS{"42": directory}, read: func(string) ([]fs.DirEntry, error) { return nil, fault }}
			if _, err := readProcessTasksIn(context.Background(), source, "42"); !errors.Is(err, ErrQualification) {
				t.Fatalf("accepted uncertain inventory: %v", err)
			}
		})
	}
	t.Run("disappears during enumeration", func(t *testing.T) {
		tree := fstest.MapFS{"42": directory}
		source := procFaultFS{FS: tree, read: func(string) ([]fs.DirEntry, error) { delete(tree, "42"); return nil, fs.ErrNotExist }}
		if tasks, err := readProcessTasksIn(context.Background(), source, "42"); err != nil || len(tasks) != 0 {
			t.Fatalf("disappeared group: %v", err)
		}
	})
	t.Run("group observability fails", func(t *testing.T) {
		source := procFaultFS{FS: fstest.MapFS{}, stat: func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }}
		if _, err := readProcessTasksIn(context.Background(), source, "42"); !errors.Is(err, ErrQualification) {
			t.Fatal("uncertain group absence accepted")
		}
	})
}
func TestProcessTaskEnumerationCancellation(t *testing.T) {
	for _, stage := range []string{"before read", "during read", "during group lookup"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tree := fstest.MapFS{"42/task/43": {Mode: fs.ModeDir | 0700}}
			source := procFaultFS{FS: tree}
			switch stage {
			case "before read":
				cancel()
			case "during read":
				source.read = func(name string) ([]fs.DirEntry, error) { cancel(); return fs.ReadDir(tree, name) }
			case "during group lookup":
				source.read = func(string) ([]fs.DirEntry, error) { return nil, fs.ErrNotExist }
				source.stat = func(name string) (fs.FileInfo, error) { cancel(); return fs.Stat(tree, name) }
			}
			if _, err := readProcessTasksIn(ctx, source, "42"); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
}
func fakeProcWorker(t *testing.T, root, pid, tid string) string {
	t.Helper()
	task := filepath.Join(root, pid, "task", tid)
	for _, dir := range []string{"fd", "ns"} {
		if err := os.MkdirAll(filepath.Join(task, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string]string{"maps": "", "mountinfo": "20 1 0:1 / / rw - tmpfs tmpfs rw\n"} {
		if err := os.WriteFile(filepath.Join(task, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/proc/self/ns/mnt", filepath.Join(task, "ns/mnt")); err != nil {
		t.Fatal(err)
	}
	return task
}
func TestBothScannersFenceObservableGroupWithoutTasks(t *testing.T) {
	for _, missing := range []bool{true, false} {
		t.Run(map[bool]string{true: "missing", false: "empty"}[missing], func(t *testing.T) {
			root := t.TempDir()
			fakeProcWorker(t, root, "10", "11")
			for _, scan := range []func() error{func() error {
				return noBlockUsersIn(context.Background(), root, BlockRecord{FileDevice: 7, FileInode: 9})
			}, func() error { return loopMountedIn(context.Background(), root, 123) }} {
				if err := scan(); err != nil {
					t.Fatalf("valid unrelated worker rejected: %v", err)
				}
			}
			path := filepath.Join(root, "20")
			if !missing {
				path = filepath.Join(path, "task")
			}
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := noBlockUsersIn(context.Background(), root, BlockRecord{FileDevice: 7, FileInode: 9}); !errors.Is(err, ErrQualification) {
				t.Fatalf("reference scan skipped observable group: %v", err)
			}
			if err := loopMountedIn(context.Background(), root, 123); !errors.Is(err, ErrQualification) {
				t.Fatalf("namespace scan skipped observable group: %v", err)
			}
		})
	}
}
func TestBothScannersHonorCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root := t.TempDir()
	if err := noBlockUsersIn(ctx, root, BlockRecord{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := loopMountedIn(ctx, root, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
