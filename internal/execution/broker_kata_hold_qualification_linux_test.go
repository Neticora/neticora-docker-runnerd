//go:build linux && runnerd_broker_qualification

package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/broker"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
)

// The trusted lab parent holds an original inode reference. The controller gets
// neither its FD nor a privileged fault selector. Read-only observation must
// prove quarantine and retained capacity before releasing that reference.
func phaseE2HoldBlock(t *testing.T, p phaseDPublic, state, ledger string) func() error {
	if os.Getenv("RUNNERD_E2_HOLD_BLOCK") != "1" {
		return func() error { return nil }
	}
	if p.KataProfileID == "" || len(p.Starts) != 1 || p.ExpectQuarantine {
		t.Fatal("held block requires one ordinary Kata lifecycle")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- phaseE2ObserveHeldBlock(ctx, p, state, ledger) }()
	return func() error {
		defer cancel()
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
func phaseE2ObserveHeldBlock(ctx context.Context, p phaseDPublic, state, ledger string) error {
	var m katalinux.Manifest
	if json.Unmarshal(p.KataManifest, &m) != nil || m.Storage.Block == nil {
		return fmt.Errorf("missing Kata block manifest")
	}
	var held *os.File
	defer func() {
		if held != nil {
			held.Close()
		}
	}()
	var original syscall.Stat_t
	var name string
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		files, err := filepath.Glob(filepath.Join(ledger, "resources", "*.json"))
		if err != nil {
			return err
		}
		for _, file := range files {
			raw, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			var record struct {
				Name, State, Pending, ResourceID string
				Binding                          broker.Binding
				Operations                       map[string]broker.ExecutionGrantRequest
			}
			if json.Unmarshal(raw, &record) != nil {
				return fmt.Errorf("invalid held resource record")
			}
			if record.Binding.ExecutionID != p.Starts[0].Spec.ExecutionId {
				continue
			}
			if held == nil {
				// Hold only after the original disk allocation has its durable record.
				blockRaw, err := os.ReadFile(filepath.Join(p.KataEvidenceDirectory, "block-slots.json"))
				if os.IsNotExist(err) {
					continue
				}
				if err != nil {
					return err
				}
				var index struct {
					Record struct {
						Active map[string]struct {
							Record katalinux.BlockRecord `json:"record"`
						} `json:"active"`
					} `json:"record"`
				}
				if json.Unmarshal(blockRaw, &index) != nil {
					return fmt.Errorf("invalid block ownership index")
				}
				block, exists := index.Record.Active[record.Name]
				if !exists {
					continue
				}
				if block.Record.Phase != "ready" {
					continue
				}
				held, err = os.Open(filepath.Join(m.Storage.Block.Pool.Root, record.Name+".raw"))
				if err != nil {
					return err
				}
				if syscall.Fstat(int(held.Fd()), &original) != nil || uint64(original.Dev) != block.Record.FileDevice || original.Ino != block.Record.FileInode {
					return fmt.Errorf("held disk identity differs")
				}
				name = record.Name
			}
			if record.Name != name || record.State != "QUARANTINED" || record.Pending == "" || record.Pending != record.Operations["RemoveExecution"].OperationID {
				continue
			}
			// Exact original raw inode, consumed removal, allocation index and native
			// reservation must remain before the trusted reference can be dropped.
			var current syscall.Stat_t
			if syscall.Stat(filepath.Join(m.Storage.Block.Pool.Root, name+".raw"), &current) != nil || current.Dev != original.Dev || current.Ino != original.Ino {
				return fmt.Errorf("uncertain disk deleted or replaced")
			}
			slotsRaw, err := os.ReadFile(filepath.Join(p.KataEvidenceDirectory, "block-slots.json"))
			if err != nil {
				return err
			}
			var slots struct {
				Record struct {
					Active map[string]json.RawMessage `json:"active"`
				} `json:"record"`
			}
			if json.Unmarshal(slotsRaw, &slots) != nil || slots.Record.Active[name] == nil {
				return fmt.Errorf("uncertain block reservation released")
			}
			db, err := sql.Open("sqlite", "file:"+filepath.Join(p.State, "journal.db")+"?mode=ro")
			if err != nil {
				return err
			}
			var nativeState string
			var pending, reserved int
			err = db.QueryRowContext(ctx, "SELECT state,cleanup_pending FROM executions WHERE execution_id=?", p.Starts[0].Spec.ExecutionId).Scan(&nativeState, &pending)
			if err == nil {
				err = db.QueryRowContext(ctx, "SELECT count(*) FROM reservations WHERE released=0").Scan(&reserved)
			}
			db.Close()
			if err != nil {
				return err
			}
			if pending != 1 || nativeState == "cleaned" || reserved != 1 {
				return fmt.Errorf("uncertain disposal released native capacity")
			}
			proof := map[string]any{"purpose": "runnerd-e2-held-original-block", "resourceId": record.ResourceID, "operationId": record.Pending, "name": name, "fileDevice": uint64(original.Dev), "fileInode": original.Ino, "brokerState": record.State, "nativeState": nativeState, "cleanupPending": pending, "unreleasedReservations": reserved, "allocationReserved": true, "productionAdmission": false}
			raw, _ = json.MarshalIndent(proof, "", "  ")
			if err = os.WriteFile(filepath.Join(state, "held-block-evidence.json"), append(raw, '\n'), 0600); err != nil {
				return err
			}
			// Closing the fixture reference grants no operation: the controller can only
			// reconcile its already consumed RemoveExecution and original resource.
			return held.Close()
		}
	}
}
