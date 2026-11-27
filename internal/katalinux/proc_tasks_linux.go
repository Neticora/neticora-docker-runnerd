//go:build linux

package katalinux

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"strconv"
)

// A leader's task directory can disappear while worker threads remain alive.
// Only absence of the thread-group directory permits skipping the group. An
// empty, inaccessible or missing task inventory for an observable group is not
// evidence that its mappings, descriptors or mount namespaces are gone.
func readProcessTasks(ctx context.Context, pid string) ([]os.DirEntry, error) {
	return readProcessTasksIn(ctx, os.DirFS("/proc"), pid)
}

// Injection is confined to this internal helper. Production always uses /proc;
// no environment variable or customer configuration can replace the trust root.
func readProcessTasksIn(ctx context.Context, proc fs.FS, pid string) ([]os.DirEntry, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if n, err := strconv.ParseUint(pid, 10, 64); err != nil || n == 0 {
		return nil, ErrQualification
	}
	tasks, err := fs.ReadDir(proc, path.Join(pid, "task"))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err == nil && len(tasks) != 0 {
		return tasks, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, ErrQualification
	}
	_, err = fs.Stat(proc, pid)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return nil, ErrQualification
}
