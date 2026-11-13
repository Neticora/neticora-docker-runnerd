//go:build linux

package broker

import (
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

// A root-owned qualification configuration may kill this broker at an exact
// durable-operation boundary. There is no IPC selector and no shipping backend.
func qualificationCheckpoint(file string) func(string, ExecutionGrantRequest) error {
	return func(point string, r ExecutionGrantRequest) error {
		if file == "" {
			return nil
		}
		if !runtimeQualification || !filepath.IsAbs(file) || filepath.Clean(file) != file || hostfs.CheckAncestors(filepath.Dir(file)) != nil {
			return ErrRejected
		}
		if _, err := os.Lstat(file + ".consumed"); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		if _, err := os.Lstat(file); os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
		raw, err := hostfs.ReadPrivate(file, 4096)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		var f struct {
			Operation   string `json:"operation"`
			Point       string `json:"point"`
			ExecutionID string `json:"executionId"`
		}
		if decode(raw, &f) != nil || executionState(f.Operation) == "" || (f.Point != "before-effect" && f.Point != "after-effect") || f.ExecutionID == "" {
			return ErrRejected
		}
		if f.Operation != r.Operation || f.Point != point || f.ExecutionID != r.ExecutionID {
			return nil
		}
		// O_EXCL hardlink consumption cannot overwrite another crash receipt.
		if err = os.Link(file, file+".consumed"); err != nil {
			return err
		}
		dir, err := os.Open(filepath.Dir(file))
		if err != nil {
			return err
		}
		defer dir.Close()
		if err = dir.Sync(); err != nil {
			return err
		}
		if err = os.Remove(file); err != nil {
			return err
		}
		if err = dir.Sync(); err != nil {
			return err
		}
		slog.Warn("qualification broker SIGKILL", "point", point, "operation", r.Operation, "operationId", r.OperationID)
		return syscall.Kill(os.Getpid(), syscall.SIGKILL)
	}
}
