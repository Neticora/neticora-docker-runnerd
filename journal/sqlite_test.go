//go:build linux

package journal

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
)

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
func recovery(t *testing.T, dir string, o Options) *SQLiteStore {
	t.Helper()
	o = testOptions(o)
	s, err := OpenRecovery(context.Background(), dir, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func testOptions(o Options) Options {
	if o.ReservationLimits == (agent.ReservationLimits{}) {
		o.ReservationLimits = agent.ReservationLimits{CPUMillis: 100000, MemoryBytes: 1 << 40, StorageBytes: 1 << 42, Slots: 100}
	}
	return o
}
func TestRecoveryStoreConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) agent.RecoveryStore { return recovery(t, privateDir(t), Options{}) })
}

func TestDuplicateReceiptsRecoverUnderOutboxPressureWithoutWrites(t *testing.T) {
	for _, limit := range []string{"events", "bytes"} {
		t.Run(limit, func(t *testing.T) {
			ctx := context.Background()
			start := storetest.Start(t, "a")
			other := storetest.Start(t, "b")
			event := storetest.Event(t, other, 1, "running")
			options := Options{}
			if limit == "events" {
				options.MaxOutboxEvents = 1
			} else {
				options.MaxOutboxBytes = int64(len(event))
			}
			s := recovery(t, privateDir(t), options)
			storetest.Reconcile(t, s, storetest.Scope, "1")
			original, err := s.AcceptCommand(ctx, storetest.Scope, start)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.AcceptCommand(ctx, storetest.Scope, other); err != nil {
				t.Fatal(err)
			}
			if err = s.RecordObservation(ctx, storetest.Scope, event); err != nil {
				t.Fatal(err)
			}
			if h := s.Health(ctx); h.Ready || h.Reason != "outbox-pressure" {
				t.Fatal("outbox pressure missing", h)
			}
			revision := s.anchor.Revision
			s.fault = func(stage string) error {
				if stage == "before-commit" {
					return errors.New("receipt replay must not write")
				}
				return nil
			}
			replay, err := s.AcceptCommand(ctx, storetest.Scope, start)
			if err != nil || !replay.Duplicate || replay.CommandID != original.CommandID || replay.Generation != original.Generation || replay.PayloadHash != original.PayloadHash {
				t.Fatal("durable receipt lost under pressure", replay, err)
			}
			if s.anchor.Revision != revision || count(t, s, "commands") != 2 || count(t, s, "reservations") != 2 {
				t.Fatal("receipt replay mutated journal")
			}
			if _, err = s.AcceptCommand(ctx, storetest.Scope, storetest.Start(t, "new")); !errors.Is(err, agent.ErrCapacity) {
				t.Fatal("replay admitted new command", err)
			}
			changed := storetest.Object(t, start)
			changed["spec"].(map[string]any)["poolId"] = "different-pool"
			if _, err = s.AcceptCommand(ctx, storetest.Scope, storetest.Encode(t, "HostCommand", changed)); !errors.Is(err, agent.ErrConflict) {
				t.Fatal("pressure hid conflicting duplicate", err)
			}
			wrong := storetest.Scope
			wrong.HostID = "other-host"
			if _, err = s.AcceptCommand(ctx, wrong, start); !errors.Is(err, agent.ErrConflict) {
				t.Fatal("duplicate bypassed host binding", err)
			}
		})
	}
}

func TestCanceledReceiptReadsDoNotQuarantineHealthyStore(t *testing.T) {
	for _, stage := range []string{"integrity", "lookup"} {
		t.Run(stage, func(t *testing.T) {
			s := recovery(t, privateDir(t), Options{})
			start := accepted(t, s)
			ctx := context.Background()
			revision := s.anchor.Revision
			var held *sql.Conn
			borrow := func() error { var err error; held, err = s.db.Conn(ctx); return err }
			if stage == "integrity" {
				if err := borrow(); err != nil {
					t.Fatal(err)
				}
			} else {
				s.fault = func(point string) error {
					if point == "receipt-lookup" {
						return borrow()
					}
					return nil
				}
			}
			defer func() {
				if held != nil {
					_ = held.Close()
				}
			}()
			deadline, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			receipt, err := s.AcceptCommand(deadline, storetest.Scope, start)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) || receipt.CommandID != "" {
				t.Fatal("receipt read did not time out safely", receipt, err)
			}
			if held == nil {
				t.Fatal("test did not occupy SQLite connection at requested stage")
			}
			if err = held.Close(); err != nil {
				t.Fatal(err)
			}
			held = nil
			s.fault = nil
			if s.failed.Load() || !s.Health(ctx).Ready {
				t.Fatal("canceled read quarantined healthy store")
			}
			receipt, err = s.AcceptCommand(ctx, storetest.Scope, start)
			if err != nil || !receipt.Duplicate || receipt.CommandID != "cmd-a" {
				t.Fatal("receipt not recoverable after cancellation", receipt, err)
			}
			if s.anchor.Revision != revision || count(t, s, "commands") != 1 || count(t, s, "reservations") != 1 {
				t.Fatal("canceled/read-only replay mutated journal")
			}
		})
	}
}

func TestReceiptReadFailureDoesNotHideIntegrityErrorsBehindCancellation(t *testing.T) {
	for _, cause := range []error{agent.ErrRecoveryRequired, agent.ErrStoreUnavailable, os.ErrNotExist} {
		s := recovery(t, privateDir(t), Options{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := s.receiptReadFailure(ctx, cause); !errors.Is(err, agent.ErrStoreUnavailable) || !s.failed.Load() {
			t.Fatal("canceled context hid integrity failure", cause, err)
		}
	}
}

func TestStoredReceiptMetadataMismatchQuarantinesStore(t *testing.T) {
	for _, column := range []string{"payload_hash", "execution_id", "generation", "kind"} {
		t.Run(column, func(t *testing.T) {
			s := recovery(t, privateDir(t), Options{})
			start := accepted(t, s)
			ctx := context.Background()
			if _, err := s.AcceptCommand(ctx, storetest.Scope, storetest.Start(t, "b")); err != nil {
				t.Fatal(err)
			}
			var query string
			var value string
			switch column {
			case "payload_hash":
				query = "UPDATE commands SET payload_hash=? WHERE command_id='cmd-a'"
				value = strings.Repeat("b", 64)
			case "execution_id":
				query = "UPDATE commands SET execution_id=? WHERE command_id='cmd-a'"
				value = "exec-b"
			case "generation":
				// Keep the foreign key valid while corrupting only command metadata.
				if _, err := s.db.Exec(`INSERT INTO executions(execution_id,generation,identity,session_epoch,endpoint_identity,attempt_id,command_id,command)
			 SELECT execution_id,'2',identity,session_epoch,endpoint_identity,'metadata-attempt','metadata-command',command FROM executions WHERE command_id='cmd-a'`); err != nil {
					t.Fatal(err)
				}
				query = "UPDATE commands SET generation=? WHERE command_id='cmd-a'"
				value = "2"
			case "kind":
				query = "UPDATE commands SET kind=? WHERE command_id='cmd-a'"
				value = "cleanup"
			}
			if _, err := s.db.Exec(query, value); err != nil {
				t.Fatal(err)
			}
			revision := s.anchor.Revision
			if receipt, err := s.AcceptCommand(ctx, storetest.Scope, start); !errors.Is(err, agent.ErrStoreUnavailable) || receipt.CommandID != "" {
				t.Fatal("inconsistent stored metadata produced receipt", column, receipt, err)
			}
			if !s.failed.Load() || s.Health(ctx).Ready {
				t.Fatal("metadata inconsistency did not fence store")
			}
			if s.anchor.Revision != revision {
				t.Fatal("invalid metadata replay changed revision")
			}
		})
	}
}

func TestReceiptReplayRestartHelper(t *testing.T) {
	dir := os.Getenv("RUNNERD06_RECEIPT_REPLAY_DIR")
	if dir == "" {
		return
	}
	s := recovery(t, dir, Options{})
	ctx := context.Background()
	start, err := os.ReadFile(filepath.Join(dir, "receipt-command.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "receipt-expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected agent.Receipt
	if err = json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AcceptCommand(ctx, storetest.Scope, start); !errors.Is(err, agent.ErrRecoveryRequired) {
		t.Fatal("restart replay skipped reconciliation", err)
	}
	storetest.Reconcile(t, s, storetest.Scope, "2", agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "0"})
	revision := s.anchor.Revision
	s.fault = func(stage string) error {
		if stage == "before-commit" {
			return errors.New("restart receipt replay must not write")
		}
		return nil
	}
	actual, err := s.AcceptCommand(ctx, storetest.Scope, start)
	if err != nil || !actual.Duplicate || actual.CommandID != expected.CommandID || actual.PayloadHash != expected.PayloadHash || actual.Generation != expected.Generation {
		t.Fatal("process restart lost original receipt", actual, expected, err)
	}
	if s.anchor.Revision != revision || count(t, s, "commands") != 1 || count(t, s, "reservations") != 1 {
		t.Fatal("restart replay mutated durable identity")
	}
}

func TestDuplicateReceiptRecoveryAfterProcessRestart(t *testing.T) {
	dir := privateDir(t)
	s := recovery(t, dir, Options{})
	ctx := context.Background()
	storetest.Reconcile(t, s, storetest.Scope, "1")
	start := storetest.Start(t, "a")
	expected, err := s.AcceptCommand(ctx, storetest.Scope, start)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(expected)
	if err = os.WriteFile(filepath.Join(dir, "receipt-command.json"), start, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "receipt-expected.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestReceiptReplayRestartHelper$")
	command.Env = append(os.Environ(), "RUNNERD06_RECEIPT_REPLAY_DIR="+dir)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("receipt recovery failed in new process: %v\n%s", err, out)
	}
}

func TestDuplicateReceiptsDoNotBypassQuarantineOrIntegrity(t *testing.T) {
	for _, damage := range []string{"failed", "uncertain", "missing-database", "missing-anchor", "stale-anchor", "corrupt-command"} {
		t.Run(damage, func(t *testing.T) {
			s := recovery(t, privateDir(t), Options{})
			start := accepted(t, s)
			ctx := context.Background()
			switch damage {
			case "failed":
				s.failed.Store(true)
			case "uncertain":
				s.anchorUncertain = true
			case "missing-anchor":
				if err := os.Rename(filepath.Join(s.dir, anchorName), filepath.Join(s.dir, "anchor.retained")); err != nil {
					t.Fatal(err)
				}
			case "missing-database":
				if err := os.Rename(filepath.Join(s.dir, databaseName), filepath.Join(s.dir, "database.retained")); err != nil {
					t.Fatal(err)
				}
			case "stale-anchor":
				old := s.anchor
				old.Revision--
				raw, _ := json.Marshal(old)
				if err := os.WriteFile(filepath.Join(s.dir, anchorName), raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt-command":
				if _, err := s.db.Exec("UPDATE commands SET payload=?", []byte("corrupt retained command")); err != nil {
					t.Fatal(err)
				}
			}
			if receipt, err := s.AcceptCommand(ctx, storetest.Scope, start); err == nil || receipt.CommandID != "" {
				t.Fatal("unsafe store returned durable receipt", damage, receipt, err)
			}
		})
	}
}

func TestCleanupBackpressureRetainsOwnershipUntilAckAndRetry(t *testing.T) {
	for _, limit := range []string{"events", "bytes"} {
		t.Run(limit, func(t *testing.T) {
			ctx := context.Background()
			start := storetest.Start(t, "a")
			running := storetest.Event(t, start, 1, "running")
			pending := storetest.Event(t, start, 2, "cleanup-pending")
			cleaned := storetest.Event(t, start, 3, "cleaned")
			options := Options{}
			if limit == "events" {
				options.MaxOutboxEvents = 1
			} else {
				options.MaxOutboxBytes = int64(max(len(running), len(pending), len(cleaned)))
			}
			s := recovery(t, privateDir(t), options)
			storetest.Reconcile(t, s, storetest.Scope, "1")
			if _, err := s.AcceptCommand(ctx, storetest.Scope, start); err != nil {
				t.Fatal(err)
			}
			if err := s.RecordObservation(ctx, storetest.Scope, running); err != nil {
				t.Fatal(err)
			}
			if err := s.RequireCleanup(ctx, storetest.Scope, pending); !errors.Is(err, agent.ErrCapacity) {
				t.Fatal("cleanup obligation exceeded hard outbox bound", err)
			}
			if count(t, s, "cleanup_tasks") != 0 || count(t, s, "outbox_events") != 1 {
				t.Fatal("failed cleanup partially committed")
			}
			var released bool
			if err := s.db.QueryRow("SELECT released FROM reservations").Scan(&released); err != nil || released {
				t.Fatal("blocked cleanup released ownership", err)
			}
			if events, err := s.PendingEvents(ctx, agent.EventPage{ExecutionID: "exec-a", Generation: "1", AfterSequence: "0", Limit: 10}); err != nil || len(events) != 1 || !bytes.Equal(events[0], running) {
				t.Fatal("pressure evicted prior facts", err)
			}
			if err := s.AckEvents(ctx, storetest.Scope, agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "1"}); err != nil {
				t.Fatal(err)
			}
			if err := s.RequireCleanup(ctx, storetest.Scope, pending); err != nil {
				t.Fatal("ACK did not unblock original cleanup obligation", err)
			}
			proof := storetest.Proof(t, cleaned, "1")
			if err := s.CompleteCleanup(ctx, storetest.Scope, cleaned, proof); !errors.Is(err, agent.ErrCapacity) {
				t.Fatal("cleanup completion exceeded hard bound", err)
			}
			var complete bool
			if err := s.db.QueryRow("SELECT complete FROM cleanup_tasks").Scan(&complete); err != nil || complete {
				t.Fatal("failed completion discarded obligation", err)
			}
			if err := s.db.QueryRow("SELECT released FROM reservations").Scan(&released); err != nil || released {
				t.Fatal("uncommitted cleaned event released reservation", err)
			}
			if err := s.AckEvents(ctx, storetest.Scope, agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "2"}); err != nil {
				t.Fatal(err)
			}
			if err := s.CompleteCleanup(ctx, storetest.Scope, cleaned, proof); err != nil {
				t.Fatal("ACK did not unblock identical cleaned event", err)
			}
			if err := s.db.QueryRow("SELECT released FROM reservations").Scan(&released); err != nil || !released {
				t.Fatal("durable cleaned event did not release reservation", err)
			}
		})
	}
}

func TestCreationUsesReportedAdmissionGate(t *testing.T) {
	for _, cause := range []string{"unconfigured-limits", "reduced-limits", "outbox-events", "outbox-bytes"} {
		t.Run(cause, func(t *testing.T) {
			dir := privateDir(t)
			ctx := context.Background()
			start := storetest.Start(t, "a")
			other := storetest.Start(t, "b")
			event := storetest.Event(t, other, 1, "running")
			options := Options{}
			if cause == "outbox-events" {
				options.MaxOutboxEvents = 1
			}
			if cause == "outbox-bytes" {
				options.MaxOutboxBytes = int64(len(event))
			}
			s := recovery(t, dir, options)
			storetest.Reconcile(t, s, storetest.Scope, "1")
			if _, err := s.AcceptCommand(ctx, storetest.Scope, start); err != nil {
				t.Fatal(err)
			}
			if err := s.PutStartIntent(ctx, storetest.Scope, storetest.Intent(t, start)); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(cause, "outbox-") {
				if _, err := s.AcceptCommand(ctx, storetest.Scope, other); err != nil {
					t.Fatal(err)
				}
				if err := s.RecordObservation(ctx, storetest.Scope, event); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				limits := agent.ReservationLimits{}
				if cause == "reduced-limits" {
					limits = agent.ReservationLimits{CPUMillis: 1, MemoryBytes: 1, StorageBytes: 1, Slots: 1}
				}
				var err error
				s, err = OpenRecovery(ctx, dir, Options{ReservationLimits: limits})
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				storetest.Reconcile(t, s, storetest.Scope, "2", agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "0"})
			}
			h := s.Health(ctx)
			if h.Ready {
				t.Fatal("admission pressure not reported", cause)
			}
			if receipt, err := s.AcceptCommand(ctx, storetest.Scope, start); err != nil || !receipt.Duplicate {
				t.Fatal("admission pressure blocked durable receipt", receipt, err)
			}
			a := Authority{TenantID: "tenant-a", HostID: "host-a", SessionEpoch: "1", EndpointIdentity: "engine-a", KeyID: "key-a"}
			if err := s.ClaimCreation(ctx, start, a); !errors.Is(err, agent.ErrCapacity) {
				t.Fatal("creation bypassed", cause, h, err)
			}
			markers, err := filepath.Glob(filepath.Join(dir, "*.creation.json"))
			if err != nil || len(markers) != 0 {
				t.Fatal("denied creation crossed permanent fence", err)
			}
			if strings.HasPrefix(cause, "outbox-") {
				pending, err := s.PendingEvents(ctx, agent.EventPage{ExecutionID: "exec-b", Generation: "1", AfterSequence: "0", Limit: 10})
				if err != nil || len(pending) != 1 {
					t.Fatal("admission pressure blocked existing event delivery", err)
				}
				if err = s.AckEvents(ctx, storetest.Scope, agent.Watermark{ExecutionID: "exec-b", Generation: "1", ContiguousSequence: "1"}); err != nil {
					t.Fatal(err)
				}
				if !s.Health(ctx).Ready {
					t.Fatal("ACK did not recover launch readiness")
				}
				if err = s.ClaimCreation(ctx, start, a); err != nil {
					t.Fatal("recovered gate rejected existing intent", err)
				}
			}
		})
	}
}

func TestBackupUsesMaintenanceDeadlineAndAllowsRecoveryWrites(t *testing.T) {
	s := recovery(t, privateDir(t), Options{WriteTimeout: 500 * time.Millisecond, MaintenanceTimeout: 5 * time.Second})
	ctx := context.Background()
	start := accepted(t, s)
	if err := s.PutStartIntent(ctx, storetest.Scope, storetest.Intent(t, start)); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	resume := make(chan struct{})
	defer onceResume(resume)()
	var once sync.Once
	s.fault = func(stage string) error {
		if stage == "backup-snapshot" {
			once.Do(func() { close(entered); <-resume })
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- s.Backup(ctx, "backup-online.db") }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("backup did not establish snapshot")
	}
	if h := s.Health(ctx); h.Ready || h.Reason != "maintenance" {
		t.Fatal("maintenance did not fence launch admission", h)
	}
	if receipt, err := s.AcceptCommand(ctx, storetest.Scope, start); err != nil || !receipt.Duplicate {
		t.Fatal("maintenance blocked durable receipt replay", receipt, err)
	}
	a := Authority{TenantID: "tenant-a", HostID: "host-a", SessionEpoch: "1", EndpointIdentity: "engine-a", KeyID: "key-a"}
	if err := s.ClaimCreation(ctx, start, a); !errors.Is(err, agent.ErrMaintenance) {
		t.Fatal("backup admitted creation", err)
	}
	first := storetest.Event(t, start, 1, "running")
	if err := s.RecordObservation(ctx, storetest.Scope, first); err != nil {
		t.Fatal("backup blocked recovery observation", err)
	}
	if events, err := s.PendingEvents(ctx, agent.EventPage{ExecutionID: "exec-a", Generation: "1", AfterSequence: "0", Limit: 10}); err != nil || len(events) != 1 {
		t.Fatal("backup blocked event delivery", err)
	}
	if err := s.AckEvents(ctx, storetest.Scope, agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "1"}); err != nil {
		t.Fatal("backup blocked ACK", err)
	}
	if err := s.RequireCleanup(ctx, storetest.Scope, storetest.Event(t, start, 2, "cleanup-pending")); err != nil {
		t.Fatal("backup blocked cleanup obligation", err)
	}
	cleaned := storetest.Event(t, start, 3, "cleaned")
	if err := s.CompleteCleanup(ctx, storetest.Scope, cleaned, storetest.Proof(t, cleaned, "1")); err != nil {
		t.Fatal("backup blocked verified cleanup", err)
	}
	time.Sleep(600 * time.Millisecond)
	close(resume)
	if err := <-done; err != nil {
		t.Fatal("maintenance inherited short write timeout", err)
	}
	if !s.Health(ctx).Ready {
		t.Fatal("backup did not restore admission health")
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, "backup-online.db.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest backupManifest
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Anchor.Revision >= s.anchor.Revision {
		t.Fatal("backup did not retain the original snapshot revision")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	dest := privateDir(t)
	if err = RestoreBackup(ctx, s.dir, "backup-online.db", dest); err != nil {
		t.Fatal(err)
	}
	restored := recovery(t, dest, Options{})
	records, err := restored.Incomplete(ctx, agent.ExecutionCursor{}, 10)
	if err != nil || len(records) != 1 || records[0].State != "accepted" || records[0].LastSequence != "0" {
		t.Fatal("backup mixed later writes into snapshot", records, err)
	}
}

func onceResume(ch chan struct{}) func() {
	return func() {
		select {
		case <-ch:
		default:
			close(ch)
		}
	}
}

func TestMaintenanceDeadlineAndCheckpointContentionDoNotFenceRecovery(t *testing.T) {
	s := recovery(t, privateDir(t), Options{WriteTimeout: 100 * time.Millisecond, MaintenanceTimeout: 200 * time.Millisecond})
	ctx := context.Background()
	start := accepted(t, s)
	s.fault = func(stage string) error {
		if stage == "backup-snapshot" {
			time.Sleep(250 * time.Millisecond)
		}
		return nil
	}
	if err := s.Backup(ctx, "backup-expired.db"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("maintenance deadline not enforced", err)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "backup-expired.db.json")); !os.IsNotExist(err) {
		t.Fatal("expired backup published manifest")
	}
	if !s.Health(ctx).Ready {
		t.Fatal("maintenance cancellation poisoned healthy journal")
	}
	reader, err := sql.Open("sqlite", filepath.Join(s.dir, databaseName))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	reader.SetMaxOpenConns(1)
	if _, err = reader.Exec("BEGIN"); err != nil {
		t.Fatal(err)
	}
	defer reader.Exec("ROLLBACK")
	var revision int
	if err = reader.QueryRow("SELECT revision FROM metadata").Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordObservation(ctx, storetest.Scope, storetest.Event(t, start, 1, "running")); err != nil {
		t.Fatal(err)
	}
	result, err := s.Checkpoint(ctx)
	if err != nil || result.Busy != 1 {
		t.Fatal("checkpoint did not report pinned-reader contention", result, err)
	}
	if !s.Health(ctx).Ready {
		t.Fatal("busy checkpoint poisoned healthy journal")
	}
	if err = s.RecordObservation(ctx, storetest.Scope, storetest.Event(t, start, 2, "exited")); err != nil {
		t.Fatal("busy checkpoint blocked recovery reporting", err)
	}
}
func accepted(t *testing.T, s *SQLiteStore) json.RawMessage {
	t.Helper()
	storetest.Reconcile(t, s, storetest.Scope, "1")
	start := storetest.Start(t, "a")
	if _, err := s.AcceptCommand(context.Background(), storetest.Scope, start); err != nil {
		t.Fatal(err)
	}
	return start
}
func count(t *testing.T, s *SQLiteStore, table string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSQLiteSettingsPermissionsAndExclusiveLock(t *testing.T) {
	dir := privateDir(t)
	s := recovery(t, dir, Options{})
	if err := s.verifyPragmas(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Force database/sql to replace the physical connection; all required
	// pragmas must be installed on the new connection too.
	s.db.SetMaxIdleConns(0)
	if err := s.verifyPragmas(context.Background()); err != nil {
		t.Fatal("replacement connection", err)
	}
	s.db.SetMaxIdleConns(1)
	if _, err := s.db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO cleanup_tasks(execution_id,generation) VALUES('missing','1')"); err == nil {
		t.Fatal("foreign key not enforced")
	}
	for _, name := range []string{databaseName, databaseName + "-wal", databaseName + "-shm", anchorName, "instance.lock"} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("unsafe %s: %v", name, err)
		}
	}
	if second, err := OpenRecovery(context.Background(), dir, Options{}); err == nil {
		second.Close()
		t.Fatal("second SQLite owner acquired installation")
	}
	if second, err := Open(dir); err == nil {
		second.Close()
		t.Fatal("file-fence journal bypassed SQLite installation lock")
	}
	var engine string
	if err := s.db.QueryRow("SELECT sqlite_version()").Scan(&engine); err != nil {
		t.Fatal(err)
	}
	t.Log("SQLite", engine)
}

func TestStateEventAndCleanupRollbackAtomically(t *testing.T) {
	for _, operation := range []string{"observation", "cleanup", "cleaned"} {
		t.Run(operation, func(t *testing.T) {
			dir := privateDir(t)
			s := recovery(t, dir, Options{})
			start := accepted(t, s)
			ctx := context.Background()
			if operation == "cleaned" {
				if err := s.RequireCleanup(ctx, storetest.Scope, storetest.Event(t, start, 1, "cleanup-pending")); err != nil {
					t.Fatal(err)
				}
			}
			before := count(t, s, "outbox_events")
			s.fault = func(stage string) error {
				if stage == "after-event" {
					return errors.New("injected transaction failure")
				}
				return nil
			}
			var err error
			switch operation {
			case "observation":
				err = s.RecordObservation(ctx, storetest.Scope, storetest.Event(t, start, 1, "running"))
			case "cleanup":
				err = s.RequireCleanup(ctx, storetest.Scope, storetest.Event(t, start, 1, "cleanup-pending"))
			case "cleaned":
				event := storetest.Event(t, start, 2, "cleaned")
				err = s.CompleteCleanup(ctx, storetest.Scope, event, storetest.Proof(t, event, "1"))
			}
			if !errors.Is(err, agent.ErrStoreUnavailable) {
				t.Fatal("fault accepted", err)
			}
			if count(t, s, "outbox_events") != before {
				t.Fatal("event partially committed")
			}
			var released bool
			if err = s.db.QueryRow("SELECT released FROM reservations").Scan(&released); err != nil || released {
				t.Fatal("reservation released before atomic cleanup", err)
			}
			if operation == "cleanup" && count(t, s, "cleanup_tasks") != 0 {
				t.Fatal("cleanup partially committed")
			}
			if operation == "cleaned" {
				var complete bool
				if err = s.db.QueryRow("SELECT complete FROM cleanup_tasks").Scan(&complete); err != nil || complete {
					t.Fatal("cleanup completion partially committed")
				}
			}
			if s.Health(ctx).Ready {
				t.Fatal("failed journal admits starts")
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s = recovery(t, dir, Options{})
			rows, err := s.Incomplete(ctx, agent.ExecutionCursor{}, 10)
			if err != nil || len(rows) != 1 {
				t.Fatal("recovery lost execution", err)
			}
			if rows[0].LastSequence != strconv.Itoa(before) {
				t.Fatal("partial state survived rollback")
			}
		})
	}
}

func TestSQLiteFullPreventsReceiptAndLaunch(t *testing.T) {
	s := recovery(t, privateDir(t), Options{})
	storetest.Reconcile(t, s, storetest.Scope, "1")
	var pages int
	if err := s.db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages)); err != nil {
		t.Fatal(err)
	}
	committed := 0
	failed := false
	for i := 0; i < 100; i++ {
		r, err := s.AcceptCommand(context.Background(), storetest.Scope, storetest.Start(t, fmt.Sprint(i)))
		if err != nil {
			if !errors.Is(err, agent.ErrStoreUnavailable) || r.CommandID != "" {
				t.Fatal("failed persistence produced ACK", r, err)
			}
			failed = true
			break
		}
		committed++
	}
	if !failed {
		t.Fatal("test did not reach actual SQLITE_FULL")
	}
	if count(t, s, "commands") != committed || count(t, s, "executions") != committed || count(t, s, "reservations") != committed {
		t.Fatal("partial command/spec/reservation commit")
	}
	if s.Health(context.Background()).Ready {
		t.Fatal("full journal admits launches")
	}
}

func TestBoundedSQLLockContention(t *testing.T) {
	s := recovery(t, privateDir(t), Options{WriteTimeout: 200 * time.Millisecond})
	storetest.Reconcile(t, s, storetest.Scope, "1")
	other, err := sql.Open("sqlite", filepath.Join(s.dir, databaseName))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err = other.Exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer other.Exec("ROLLBACK")
	started := time.Now()
	r, err := s.AcceptCommand(context.Background(), storetest.Scope, storetest.Start(t, "locked"))
	if err == nil || r.CommandID != "" {
		t.Fatal("locked database produced receipt")
	}
	if time.Since(started) > 6*time.Second {
		t.Fatal("SQLite busy retry unbounded")
	}
	if s.Health(context.Background()).Ready {
		t.Fatal("exhausted SQLite write did not fence admission")
	}
}

func TestOutboxAndDiskHeadroomNeverEvictFacts(t *testing.T) {
	s := recovery(t, privateDir(t), Options{MaxOutboxEvents: 1})
	start := accepted(t, s)
	ctx := context.Background()
	if err := s.RecordObservation(ctx, storetest.Scope, storetest.Event(t, start, 1, "running")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptCommand(ctx, storetest.Scope, storetest.Start(t, "b")); !errors.Is(err, agent.ErrCapacity) {
		t.Fatal("outbox pressure allowed new work", err)
	}
	if err := s.RequireCleanup(ctx, storetest.Scope, storetest.Event(t, start, 2, "cleanup-pending")); !errors.Is(err, agent.ErrCapacity) {
		t.Fatal("outbox overflow accepted", err)
	}
	if count(t, s, "outbox_events") != 1 || count(t, s, "cleanup_tasks") != 0 {
		t.Fatal("outbox pressure discarded or partially committed facts")
	}
	if err := s.AckEvents(ctx, storetest.Scope, agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireCleanup(ctx, storetest.Scope, storetest.Event(t, start, 2, "cleanup-pending")); err != nil {
		t.Fatal("ACK failed to recover capacity", err)
	}
	s.options.MinFreeBytes = ^uint64(0)
	if _, err := s.AcceptCommand(ctx, storetest.Scope, storetest.Start(t, "c")); !errors.Is(err, agent.ErrCapacity) {
		t.Fatal("disk margin ignored", err)
	}
	if count(t, s, "outbox_events") != 2 {
		t.Fatal("required event identity evicted")
	}
}

func TestReservationsCannotOversubscribeOrReleaseOnExit(t *testing.T) {
	s := recovery(t, privateDir(t), Options{ReservationLimits: agent.ReservationLimits{CPUMillis: 1000, MemoryBytes: 1 << 30, StorageBytes: 10 << 30, Slots: 1}})
	ctx := context.Background()
	storetest.Reconcile(t, s, storetest.Scope, "1")
	var wg sync.WaitGroup
	winner := make(chan json.RawMessage, 8)
	errs := make(chan error, 8)
	starts := make([]json.RawMessage, 8)
	for i := range starts {
		starts[i] = storetest.Start(t, fmt.Sprint(i))
	}
	for _, start := range starts {
		wg.Add(1)
		go func(raw json.RawMessage) {
			defer wg.Done()
			_, err := s.AcceptCommand(ctx, storetest.Scope, raw)
			if err == nil {
				winner <- raw
			} else {
				errs <- err
			}
		}(start)
	}
	wg.Wait()
	close(winner)
	close(errs)
	if len(winner) != 1 {
		t.Fatal("concurrent reservations oversubscribed host", len(winner))
	}
	for err := range errs {
		if !errors.Is(err, agent.ErrCapacity) {
			t.Fatal(err)
		}
	}
	start := <-winner
	if err := s.RecordObservation(ctx, storetest.Scope, storetest.Event(t, start, 1, "exited")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptCommand(ctx, storetest.Scope, storetest.Start(t, "next")); !errors.Is(err, agent.ErrCapacity) {
		t.Fatal("exit freed physical reservation", err)
	}
	if err := s.RequireCleanup(ctx, storetest.Scope, storetest.Event(t, start, 2, "cleanup-pending")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptCommand(ctx, storetest.Scope, storetest.Start(t, "next")); !errors.Is(err, agent.ErrCapacity) {
		t.Fatal("unverified cleanup freed reservation", err)
	}
	cleaned := storetest.Event(t, start, 3, "cleaned")
	if err := s.CompleteCleanup(ctx, storetest.Scope, cleaned, storetest.Proof(t, cleaned, "1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptCommand(ctx, storetest.Scope, storetest.Start(t, "next")); err != nil {
		t.Fatal("verified cleanup failed to release capacity", err)
	}
}

func TestUnconfiguredCapacityAndStaleSessionCannotLaunch(t *testing.T) {
	dir := privateDir(t)
	s, err := OpenRecovery(context.Background(), dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	storetest.Reconcile(t, s, storetest.Scope, "1")
	start := storetest.Start(t, "a")
	if _, err = s.AcceptCommand(ctx, storetest.Scope, start); !errors.Is(err, agent.ErrCapacity) {
		t.Fatal("unconfigured host capacity authorized receipt", err)
	}
	s.options.ReservationLimits = testOptions(Options{}).ReservationLimits
	if _, err = s.AcceptCommand(ctx, storetest.Scope, start); err != nil {
		t.Fatal(err)
	}
	intent := storetest.Intent(t, start)
	newScope := storetest.Scope
	newScope.SessionEpoch = "2"
	storetest.Reconcile(t, s, newScope, "2", agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "0"})
	if err = s.PutStartIntent(ctx, newScope, intent); !errors.Is(err, agent.ErrConflict) {
		t.Fatal("old-session start intent authorized", err)
	}
	if _, err = s.AcceptCommand(ctx, storetest.Scope, start); !errors.Is(err, agent.ErrConflict) {
		t.Fatal("stale authenticated session accepted", err)
	}
}

func TestFullUnsignedEventSequenceIsPreserved(t *testing.T) {
	s := recovery(t, privateDir(t), Options{})
	start := accepted(t, s)
	ctx := context.Background()
	previous := "18446744073709551614"
	if _, err := s.db.Exec("UPDATE executions SET last_sequence=?,ack_sequence=?", previous, previous); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordObservation(ctx, storetest.Scope, storetest.Event(t, start, ^uint64(0), "running")); err != nil {
		t.Fatal("uint64 sequence truncated", err)
	}
	if err := s.AckEvents(ctx, storetest.Scope, agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "18446744073709551615"}); err != nil {
		t.Fatal("uint64 watermark truncated", err)
	}
	if err := s.RecordObservation(ctx, storetest.Scope, storetest.Event(t, start, 1, "exited")); !errors.Is(err, agent.ErrConflict) {
		t.Fatal("sequence overflow wrapped", err)
	}
}

func TestRuntimeInvalidationRacingReconciliationKeepsAdmissionFenced(t *testing.T) {
	s := recovery(t, privateDir(t), Options{})
	ctx := context.Background()
	storetest.Reconcile(t, s, storetest.Scope, "1")
	h := s.Health(ctx)
	checkpoint := agent.RecoveryCheckpoint{JournalID: h.JournalID, Revision: h.Revision, Scope: storetest.Scope, InventoryGeneration: "2", ObservedAt: time.Now()}
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	s.fault = func(stage string) error {
		if stage == "before-commit" {
			once.Do(func() { close(entered); <-release })
		}
		return nil
	}
	reconciled := make(chan error, 1)
	go func() { reconciled <- s.Reconcile(ctx, checkpoint) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("reconciliation did not reach transaction barrier")
	}
	invalidated := make(chan error, 1)
	go func() { invalidated <- s.InvalidateRuntime(ctx) }()
	deadline := time.Now().Add(time.Second)
	for s.runtimeGeneration.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.runtimeGeneration.Load() == 0 {
		close(release)
		t.Fatal("invalidation did not fence immediately")
	}
	close(release)
	if err := <-reconciled; err != nil {
		t.Fatal(err)
	}
	if err := <-invalidated; err != nil {
		t.Fatal(err)
	}
	if s.Health(ctx).Ready {
		t.Fatal("stale reconciliation defeated runtime invalidation")
	}
	if _, err := s.AcceptCommand(ctx, storetest.Scope, storetest.Start(t, "late")); !errors.Is(err, agent.ErrRecoveryRequired) {
		t.Fatal("raced runtime invalidation admitted launch", err)
	}
}

func TestExpiredInventoryFencesLaunchButRetainsReporting(t *testing.T) {
	s := recovery(t, privateDir(t), Options{})
	start := accepted(t, s)
	ctx := context.Background()
	s.inventoryObservedAt = time.Now().Add(-2 * time.Minute)
	if s.Health(ctx).Ready {
		t.Fatal("expired inventory remained ready")
	}
	if _, err := s.AcceptCommand(ctx, storetest.Scope, storetest.Start(t, "b")); !errors.Is(err, agent.ErrRecoveryRequired) {
		t.Fatal("stale inventory admitted new start", err)
	}
	if err := s.PutStartIntent(ctx, storetest.Scope, storetest.Intent(t, start)); !errors.Is(err, agent.ErrRecoveryRequired) {
		t.Fatal("stale inventory authorized issuance", err)
	}
	if err := s.RecordObservation(ctx, storetest.Scope, storetest.Event(t, start, 1, "unknown")); err != nil {
		t.Fatal("inventory expiry blocked existing outcomes", err)
	}
}

func TestBackupRestoresWALAndPreservesFencesWithNewSession(t *testing.T) {
	dir := privateDir(t)
	s := recovery(t, dir, Options{})
	start := accepted(t, s)
	ctx := context.Background()
	intent := storetest.Intent(t, start)
	if err := s.PutStartIntent(ctx, storetest.Scope, intent); err != nil {
		t.Fatal(err)
	}
	a := Authority{TenantID: "tenant-a", HostID: "host-a", SessionEpoch: "1", EndpointIdentity: "engine-a", KeyID: "key-a"}
	if err := s.ClaimCreation(ctx, start, a); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordObservation(ctx, storetest.Scope, storetest.Event(t, start, 1, "running")); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(ctx, "backup-test.db"); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(ctx, "backup-test.db"); err == nil {
		t.Fatal("backup overwritten")
	}
	if err := s.Backup(ctx, "../backup-bad.db"); err == nil {
		t.Fatal("backup escaped state directory")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restoredDir := privateDir(t)
	if err := RestoreBackup(ctx, dir, "backup-test.db", restoredDir); err != nil {
		t.Fatal(err)
	}
	restored := recovery(t, restoredDir, Options{})
	rows, err := restored.Incomplete(ctx, agent.ExecutionCursor{}, 10)
	if err != nil || len(rows) != 1 || rows[0].LastSequence != "1" || !bytes.Equal(rows[0].StartRequest, intent) {
		t.Fatal("backup lost WAL data", err)
	}
	if _, err = restored.PendingEvents(ctx, agent.EventPage{ExecutionID: "exec-a", Generation: "1", AfterSequence: "0", Limit: 10}); !errors.Is(err, agent.ErrRecoveryRequired) {
		t.Fatal("restored store replayed before reconciliation")
	}
	h := restored.Health(ctx)
	c := agent.RecoveryCheckpoint{JournalID: h.JournalID, Revision: h.Revision, Scope: storetest.Scope, InventoryGeneration: "2", ObservedAt: time.Now(), ServerWatermarks: []agent.Watermark{{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "0"}}}
	if err = restored.Reconcile(ctx, c); !errors.Is(err, agent.ErrRecoveryRequired) {
		t.Fatal("stale backup reused host session", err)
	}
	newScope := storetest.Scope
	newScope.SessionEpoch = "2"
	storetest.Reconcile(t, restored, newScope, "2", c.ServerWatermarks...)
	if err = restored.PutStartIntent(ctx, newScope, intent); !errors.Is(err, agent.ErrConflict) {
		t.Fatal("old generation recovered fresh launch authority", err)
	}
	newAuthority := a
	newAuthority.SessionEpoch = "2"
	if err = restored.ClaimCreation(ctx, start, newAuthority); err == nil {
		t.Fatal("restored old start crossed create boundary")
	}
	files, err := filepath.Glob(filepath.Join(restoredDir, "*.creation.json"))
	if err != nil || len(files) != 1 {
		t.Fatal("backup lost permanent creation fence", err)
	}
	checkpoint, err := restored.Checkpoint(ctx)
	if err != nil || checkpoint.Busy != 0 {
		t.Fatal("WAL checkpoint failed", err)
	}
}

func TestSQLiteOwnerPreservesRunnerd05NeverStartedProof(t *testing.T) {
	for _, claimed := range []bool{false, true} {
		t.Run(fmt.Sprintf("creation-claimed-%t", claimed), func(t *testing.T) {
			s := recovery(t, privateDir(t), Options{})
			ctx := context.Background()
			storetest.Reconcile(t, s, storetest.Scope, "1")
			start, fence, authority, key := fixture(t)
			if _, err := s.AcceptCommand(ctx, storetest.Scope, start); err != nil {
				t.Fatal(err)
			}
			if claimed {
				if err := s.PutStartIntent(ctx, storetest.Scope, storetest.Intent(t, start)); err != nil {
					t.Fatal(err)
				}
				if err := s.ClaimCreation(ctx, start, authority); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.AcceptCommand(ctx, storetest.Scope, fence); err != nil {
				t.Fatal(err)
			}
			proof, err := s.FenceNeverStarted(ctx, start, fence, authority, key, time.Now())
			if claimed {
				if !errors.Is(err, ErrCreationClaimed) {
					t.Fatal("uncertain creation produced no-create proof", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			p := storetest.Object(t, proof)
			if p["journalVersion"] != Version {
				t.Fatal("Runnerd05 file-fence version changed")
			}
			if err = s.ClaimCreation(ctx, start, authority); err == nil {
				t.Fatal("permanent SQLite-owned fence allowed creation")
			}
		})
	}
}

func TestRestoredSnapshotCannotInventNeverStartedEvidence(t *testing.T) {
	dir := privateDir(t)
	s := recovery(t, dir, Options{})
	ctx := context.Background()
	storetest.Reconcile(t, s, storetest.Scope, "1")
	start, fence, authority, key := fixture(t)
	if _, err := s.AcceptCommand(ctx, storetest.Scope, start); err != nil {
		t.Fatal(err)
	}
	// The snapshot precedes any creation claim. Absence from the backup must
	// never establish that no creation occurred later on the former session.
	if err := s.Backup(ctx, "backup-before-create.db"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restoredDir := privateDir(t)
	if err := RestoreBackup(ctx, dir, "backup-before-create.db", restoredDir); err != nil {
		t.Fatal(err)
	}
	restored := recovery(t, restoredDir, Options{})
	newScope := storetest.Scope
	newScope.SessionEpoch = "2"
	storetest.Reconcile(t, restored, newScope, "2", agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "0"})
	command := storetest.Object(t, fence)
	command["sessionEpoch"] = "2"
	newFence := storetest.Encode(t, "HostCommand", command)
	if _, err := restored.AcceptCommand(ctx, newScope, newFence); err != nil {
		t.Fatal(err)
	}
	authority.SessionEpoch = "2"
	if _, err := restored.FenceNeverStarted(ctx, start, newFence, authority, key, time.Now()); !errors.Is(err, agent.ErrConflict) {
		t.Fatal("stale backup invented no-create evidence", err)
	}
}

func TestMissingCorruptFutureOrStaleDatabaseFailsClosed(t *testing.T) {
	for _, damage := range []string{"missing", "corrupt", "future-schema", "future-schema-rollback-mode", "stale", "unsafe-mode", "symlink", "hardlink", "sidecar-symlink"} {
		t.Run(damage, func(t *testing.T) {
			dir := privateDir(t)
			s := recovery(t, dir, Options{})
			start := accepted(t, s)
			if err := s.Backup(context.Background(), "backup-old.db"); err != nil {
				t.Fatal(err)
			}
			if err := s.PutStartIntent(context.Background(), storetest.Scope, storetest.Intent(t, start)); err != nil {
				t.Fatal(err)
			}
			if damage == "future-schema" || damage == "future-schema-rollback-mode" {
				if _, err := s.db.Exec("PRAGMA user_version=999"); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, databaseName)
			if damage == "future-schema-rollback-mode" {
				db, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec("PRAGMA journal_mode=DELETE"); err != nil {
					t.Fatal(err)
				}
				if err = db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			switch damage {
			case "missing":
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, []byte("corrupt retained evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			case "stale":
				raw, err := os.ReadFile(filepath.Join(dir, "backup-old.db"))
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "unsafe-mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".retained", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".linked"); err != nil {
					t.Fatal(err)
				}
			case "sidecar-symlink":
				if err := os.Symlink(filepath.Join(dir, "backup-old.db"), path+"-wal"); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(path)
			if reopened, err := OpenRecovery(context.Background(), dir, Options{}); err == nil {
				reopened.Close()
				t.Fatal("damaged journal opened", damage)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("failed startup rewrote evidence", damage)
			}
		})
	}
}

func TestSchemaMigrationRollsBackAndRefusesImplicitReset(t *testing.T) {
	dir := privateDir(t)
	fences, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fences.Close()
	db, err := sql.Open("sqlite", filepath.Join(dir, databaseName))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec("CREATE TABLE executions(retain_evidence TEXT)"); err != nil {
		t.Fatal(err)
	}
	s := &SQLiteStore{fences: fences, db: db, dir: dir, anchor: anchor{JournalID: "test"}}
	if err = s.migrate(context.Background(), true); err == nil {
		t.Fatal("migration conflict accepted")
	}
	var count int
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='metadata'").Scan(&count); err != nil || count != 0 {
		t.Fatal("migration partially committed", err)
	}
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='executions'").Scan(&count); err != nil || count != 1 {
		t.Fatal("existing evidence destroyed", err)
	}
}

func TestSecretsAndInvalidHashesCannotEnterJournal(t *testing.T) {
	s := recovery(t, privateDir(t), Options{})
	start := accepted(t, s)
	ctx := context.Background()
	for _, field := range []string{"bootstrap", "privateKey", "accessToken", "encryptedBootstrap"} {
		v := storetest.Object(t, start)
		v["spec"].(map[string]any)[field] = "SENSITIVE-NEVER-PERSIST"
		raw, _ := json.Marshal(v)
		if _, err := s.AcceptCommand(ctx, storetest.Scope, raw); err == nil {
			t.Fatal("secret-bearing unknown field accepted", field)
		}
	}
	v := storetest.Object(t, start)
	v["payloadHash"] = strings.Repeat("b", 64)
	raw, _ := json.Marshal(v)
	if _, err := s.AcceptCommand(ctx, storetest.Scope, raw); err == nil {
		t.Fatal("invalid logical hash persisted")
	}
	if count(t, s, "commands") != 1 {
		t.Fatal("invalid input partially committed")
	}
	if _, err := s.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{databaseName, databaseName + "-wal"} {
		raw, err := os.ReadFile(filepath.Join(s.dir, name))
		if err == nil && bytes.Contains(raw, []byte("SENSITIVE-NEVER-PERSIST")) {
			t.Fatal("plaintext credential entered journal")
		}
	}
}

func TestSQLiteCrashHelper(t *testing.T) {
	operation := os.Getenv("RUNNERD06_CRASH_OPERATION")
	if operation == "" {
		return
	}
	dir := os.Getenv("RUNNERD06_CRASH_DIR")
	stage := os.Getenv("RUNNERD06_CRASH_STAGE")
	s, err := OpenRecovery(context.Background(), dir, testOptions(Options{}))
	if err != nil {
		t.Fatal(err)
	}
	start, err := os.ReadFile(filepath.Join(dir, "test-command.json"))
	if err != nil {
		t.Fatal(err)
	}
	watermarks := []agent.Watermark(nil)
	if operation != "receipt" {
		watermarks = []agent.Watermark{{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "0"}}
	}
	storetest.Reconcile(t, s, storetest.Scope, "2", watermarks...)
	s.fault = func(point string) error {
		if point == stage {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return nil
	}
	ctx := context.Background()
	switch operation {
	case "receipt":
		_, err = s.AcceptCommand(ctx, storetest.Scope, start)
	case "intent":
		err = s.PutStartIntent(ctx, storetest.Scope, storetest.Intent(t, start))
	case "observation":
		err = s.RecordObservation(ctx, storetest.Scope, storetest.Event(t, start, 1, "running"))
	case "cleanup":
		err = s.RequireCleanup(ctx, storetest.Scope, storetest.Event(t, start, 1, "cleanup-pending"))
	case "cleaned":
		event := storetest.Event(t, start, 2, "cleaned")
		err = s.CompleteCleanup(ctx, storetest.Scope, event, storetest.Proof(t, event, "2"))
	}
	t.Fatalf("crash hook missed %s/%s: %v", operation, stage, err)
}

func TestAbruptProcessCrashAtDurabilityBoundaries(t *testing.T) {
	for _, operation := range []string{"receipt", "intent", "observation", "cleanup", "cleaned"} {
		for _, stage := range []string{"before-commit", "after-commit", "after-anchor"} {
			t.Run(operation+"/"+stage, func(t *testing.T) {
				dir := privateDir(t)
				s := recovery(t, dir, Options{})
				ctx := context.Background()
				storetest.Reconcile(t, s, storetest.Scope, "1")
				start := storetest.Start(t, "a")
				if operation != "receipt" {
					if _, err := s.AcceptCommand(ctx, storetest.Scope, start); err != nil {
						t.Fatal(err)
					}
				}
				if operation == "cleaned" {
					if err := s.RequireCleanup(ctx, storetest.Scope, storetest.Event(t, start, 1, "cleanup-pending")); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(filepath.Join(dir, "test-command.json"), start, 0600); err != nil {
					t.Fatal(err)
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(os.Args[0], "-test.run=^TestSQLiteCrashHelper$")
				cmd.Env = append(os.Environ(), "RUNNERD06_CRASH_OPERATION="+operation, "RUNNERD06_CRASH_DIR="+dir, "RUNNERD06_CRASH_STAGE="+stage)
				out, err := cmd.CombinedOutput()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
					t.Fatalf("child not killed at boundary: %v %s", err, out)
				}
				reopened, err := OpenRecovery(ctx, dir, Options{})
				if stage == "after-commit" {
					if err != nil {
						t.Fatal("uncertain committed journal unavailable for inspection", err)
					}
					defer reopened.Close()
					if h := reopened.Health(ctx); h.Ready || h.Reason != "anchor-reconciliation-required" {
						t.Fatal("uncertain anchor admitted recovery", h)
					}
					if _, err = reopened.AcceptCommand(ctx, storetest.Scope, start); !errors.Is(err, agent.ErrRecoveryRequired) {
						t.Fatal("unreviewed committed snapshot produced receipt", err)
					}
					storetest.Reconcile(t, reopened, storetest.Scope, "3", agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "0"})
				} else {
					if err != nil {
						t.Fatal("WAL crash recovery failed", err)
					}
					defer reopened.Close()
					if reopened.Health(ctx).Ready {
						t.Fatal("process restart skipped reconciliation")
					}
				}
				db, err := sql.Open("sqlite", filepath.Join(dir, databaseName))
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				committed := stage != "before-commit"
				var n int
				query := ""
				expected := 0
				switch operation {
				case "receipt":
					query = "SELECT count(*) FROM commands"
					if committed {
						expected = 1
					}
				case "intent":
					query = "SELECT count(*) FROM start_intents"
					if committed {
						expected = 1
					}
				case "observation", "cleanup":
					query = "SELECT count(*) FROM outbox_events"
					if committed {
						expected = 1
					}
				case "cleaned":
					query = "SELECT count(*) FROM outbox_events"
					expected = 1
					if committed {
						expected = 2
					}
				}
				if err = db.QueryRow(query).Scan(&n); err != nil || n != expected {
					t.Fatalf("crash lost/partially committed facts: want %d got %d: %v", expected, n, err)
				}
				if operation == "cleanup" || operation == "cleaned" {
					var pending int
					if err = db.QueryRow("SELECT cleanup_pending FROM executions").Scan(&pending); err != nil {
						t.Fatal(err)
					}
					want := 0
					if operation == "cleanup" && committed || operation == "cleaned" && !committed {
						want = 1
					}
					if pending != want {
						t.Fatal("cleanup state/event split")
					}
				}
			})
		}
	}
}
