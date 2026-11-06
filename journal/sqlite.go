package journal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

const databaseName = "journal.db"
const anchorName = "recovery.anchor.json"
const schemaVersion = 2

type Options struct {
	// Zero values select conservative defaults, never unlimited growth.
	MinFreeBytes       uint64
	MaxJournalBytes    int64
	MaxOutboxBytes     int64
	MaxOutboxEvents    int
	WriteTimeout       time.Duration
	MaintenanceTimeout time.Duration
	ReservationLimits  agent.ReservationLimits
}

func (o Options) defaults() (Options, error) {
	limits := o.ReservationLimits
	if limits != (agent.ReservationLimits{}) && (limits.CPUMillis == 0 || limits.MemoryBytes == 0 || limits.StorageBytes == 0 || limits.Slots == 0) {
		return o, errors.New("incomplete reservation ceilings")
	}
	if o.MinFreeBytes == 0 {
		o.MinFreeBytes = 64 << 20
	}
	if o.MaxJournalBytes == 0 {
		o.MaxJournalBytes = 1 << 30
	}
	if o.MaxOutboxBytes == 0 {
		o.MaxOutboxBytes = 64 << 20
	}
	if o.MaxOutboxEvents == 0 {
		o.MaxOutboxEvents = 10000
	}
	if o.WriteTimeout == 0 {
		o.WriteTimeout = 5 * time.Second
	}
	if o.MaintenanceTimeout == 0 {
		o.MaintenanceTimeout = 2 * time.Minute
	}
	if o.MaintenanceTimeout <= 0 || o.MaintenanceTimeout > 30*time.Minute {
		return o, errors.New("invalid maintenance timeout")
	}
	if o.MaxJournalBytes < 1<<20 || o.MaxOutboxBytes < 1 || o.MaxOutboxEvents < 1 || o.WriteTimeout <= 0 || o.WriteTimeout > 30*time.Second {
		return o, errors.New("invalid recovery capacity or timeout")
	}
	return o, nil
}

type anchor struct {
	JournalID string `json:"journalId"`
	Revision  int64  `json:"revision"`
}

// SQLiteStore owns the same installation lock as the existing permanent
// Runnerd05 creation journal. The SQLite connection and SQL remain private.
type SQLiteStore struct {
	fences               *Store
	db                   *sql.DB
	dir                  string
	options              Options
	gate                 chan struct{}
	maintenanceMu        sync.Mutex
	maintenance          atomic.Bool
	failed               atomic.Bool
	pending              atomic.Int64
	runtimeGeneration    atomic.Uint64
	reconciledGeneration uint64
	inventoryObservedAt  time.Time
	closed               bool
	ready                bool
	sessionReady         bool
	scope                agent.StoreScope
	anchor               anchor
	restoredEpoch        string
	anchorUncertain      bool
	// Fault injection is package-private: production callers cannot inject work
	// or runtime/network callbacks into database transactions.
	fault func(string) error
}

var _ agent.RecoveryStore = (*SQLiteStore)(nil)

func OpenRecovery(ctx context.Context, path string, options Options) (_ *SQLiteStore, err error) {
	options, err = options.defaults()
	if err != nil {
		return nil, err
	}
	fences, err := Open(path)
	if err != nil {
		return nil, err
	}
	s := &SQLiteStore{fences: fences, dir: path, options: options, gate: make(chan struct{}, 1)}
	defer func() {
		if err != nil {
			if s.db != nil {
				_ = s.db.Close()
			}
			_ = fences.Close()
		}
	}()
	if err = localStorage(path); err != nil {
		return nil, err
	}
	if err = s.checkFiles(); err != nil {
		return nil, err
	}
	_, dbErr := os.Lstat(filepath.Join(path, databaseName))
	_, anchorErr := os.Lstat(filepath.Join(path, anchorName))
	newStore := errors.Is(dbErr, os.ErrNotExist) && errors.Is(anchorErr, os.ErrNotExist)
	if !newStore && (dbErr != nil || anchorErr != nil) {
		return nil, agent.ErrRecoveryRequired
	}
	if newStore {
		id := make([]byte, 32)
		if _, err = rand.Read(id); err != nil {
			return nil, err
		}
		s.anchor = anchor{JournalID: hex.EncodeToString(id)}
		// A failed initialization leaves evidence. Never silently recreate it.
		if err = s.writeAnchor(); err != nil {
			return nil, err
		}
		if err = privateFile(filepath.Join(path, databaseName), true); err != nil {
			return nil, err
		}
	} else {
		raw, e := s.fences.root.ReadFile(anchorName)
		if e != nil || len(raw) > 4096 {
			return nil, agent.ErrRecoveryRequired
		}
		if err = json.Unmarshal(raw, &s.anchor); err != nil || s.anchor.JournalID == "" || s.anchor.Revision < 0 {
			return nil, agent.ErrRecoveryRequired
		}
	}
	u := url.URL{Scheme: "file", Path: filepath.Join(path, databaseName)}
	if !newStore {
		// Reject unsupported schemas before a journal_mode pragma could change
		// an unknown database's header. Read-only opening still includes its WAL.
		probeURI := u
		probeURI.RawQuery = url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(5000)", "temp_store(MEMORY)"}}.Encode()
		probe, e := sql.Open("sqlite", probeURI.String())
		if e != nil {
			return nil, agent.ErrStoreUnavailable
		}
		var version int
		e = probe.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version)
		closeErr := probe.Close()
		if e != nil || closeErr != nil {
			return nil, agent.ErrStoreUnavailable
		}
		if version < 1 || version > schemaVersion {
			return nil, errors.New("unsupported recovery schema; preserve database")
		}
	}
	q := url.Values{"mode": {"rw"}, "_txlock": {"immediate"}, "_pragma": {
		"busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)", "foreign_keys(ON)",
		"temp_store(MEMORY)", "wal_autocheckpoint(256)", "journal_size_limit(16777216)",
	}}
	u.RawQuery = q.Encode()
	s.db, err = sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	// One physical connection and one bounded operation owner. DSN pragmas also
	// apply if database/sql replaces that connection after an error.
	s.db.SetMaxOpenConns(1)
	s.db.SetMaxIdleConns(1)
	if err = s.db.PingContext(ctx); err != nil {
		return nil, agent.ErrStoreUnavailable
	}
	if err = s.verifyPragmas(ctx); err != nil {
		return nil, err
	}
	if err = s.migrate(ctx, newStore); err != nil {
		return nil, err
	}
	var actual anchor
	if err = s.db.QueryRowContext(ctx, "SELECT journal_id,revision FROM metadata WHERE singleton=1").Scan(&actual.JournalID, &actual.Revision); err != nil {
		return nil, agent.ErrStoreUnavailable
	}
	if actual != s.anchor {
		if actual.JournalID != s.anchor.JournalID || actual.Revision < s.anchor.Revision {
			return nil, agent.ErrRecoveryRequired
		}
		// A process may die after SQLite committed but before the anchor sync.
		// Expose committed records for reconciliation; never enable admission or
		// ordinary mutations until the trusted controller reviews this snapshot.
		s.anchor = actual
		s.anchorUncertain = true
	}
	if _, e := os.Lstat(filepath.Join(path, "recovery.restored.json")); e == nil {
		if err = privateFile(filepath.Join(path, "recovery.restored.json"), false); err != nil {
			return nil, err
		}
		raw, e := s.fences.root.ReadFile("recovery.restored.json")
		if e != nil || len(raw) > 4096 {
			return nil, agent.ErrRecoveryRequired
		}
		var restored agent.StoreScope
		if e = json.Unmarshal(raw, &restored); e != nil || !validCounter(restored.SessionEpoch, true) {
			return nil, agent.ErrRecoveryRequired
		}
		s.restoredEpoch = restored.SessionEpoch
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	var result string
	if err = s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil || result != "ok" {
		return nil, agent.ErrStoreUnavailable
	}
	if err = s.checkFiles(); err != nil {
		return nil, err
	}
	if err = syncDirectory(path); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) migrate(ctx context.Context, fresh bool) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return agent.ErrStoreUnavailable
	}
	if version > schemaVersion || (!fresh && version == 0) {
		return errors.New("unsupported recovery schema; preserve database")
	}
	if version == schemaVersion {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return agent.ErrStoreUnavailable
	}
	defer tx.Rollback()
	for next := version + 1; next <= schemaVersion; next++ {
		name := map[int]string{1: "migrations/001_initial.sql", 2: "migrations/002_peer_recovery.sql"}[next]
		raw, e := migrations.ReadFile(name)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, string(raw)); e != nil {
			return agent.ErrStoreUnavailable
		}
		if next == 1 {
			if _, e = tx.ExecContext(ctx, "INSERT INTO metadata(singleton,journal_id,revision) VALUES(1,?,0)", s.anchor.JournalID); e != nil {
				return agent.ErrStoreUnavailable
			}
		}
		if _, e = tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", next)); e != nil {
			return agent.ErrStoreUnavailable
		}
	}
	return tx.Commit()
}

func (s *SQLiteStore) verifyPragmas(ctx context.Context) error {
	var mode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		return agent.ErrStoreUnavailable
	}
	for name, want := range map[string]int{"synchronous": 2, "foreign_keys": 1, "busy_timeout": 5000, "temp_store": 2} {
		var got int
		if err := s.db.QueryRowContext(ctx, "PRAGMA "+name).Scan(&got); err != nil || got != want {
			return agent.ErrStoreUnavailable
		}
	}
	return nil
}

func (s *SQLiteStore) checkFiles() error {
	for _, name := range []string{databaseName, databaseName + "-wal", databaseName + "-shm", databaseName + "-journal", anchorName} {
		if _, err := os.Lstat(filepath.Join(s.dir, name)); errors.Is(err, os.ErrNotExist) {
			if s.db != nil && (name == databaseName || name == anchorName) {
				return agent.ErrRecoveryRequired
			}
			continue
		} else if err != nil {
			return err
		}
		if err := privateFile(filepath.Join(s.dir, name), false); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (s *SQLiteStore) writeAnchor() error {
	// Atomic replacement, using a random private temporary in the protected
	// installation directory. A lagging/missing anchor blocks startup.
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	name := ".recovery-anchor-" + hex.EncodeToString(id)
	f, err := s.fences.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer s.fences.root.Remove(name)
	raw, err := json.Marshal(s.anchor)
	if err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err == nil {
		err = s.fences.root.Rename(name, anchorName)
	}
	if err == nil {
		err = syncDirectory(s.dir)
	}
	return err
}

func (s *SQLiteStore) acquire(ctx context.Context) (context.Context, func(), error) {
	return s.acquireWithin(ctx, s.options.WriteTimeout)
}

func (s *SQLiteStore) acquireWithin(ctx context.Context, timeout time.Duration) (context.Context, func(), error) {
	if s.pending.Add(1) > 64 {
		s.pending.Add(-1)
		return ctx, func() {}, agent.ErrStoreUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	select {
	case s.gate <- struct{}{}:
		if s.closed {
			<-s.gate
			s.pending.Add(-1)
			cancel()
			return ctx, func() {}, agent.ErrStoreUnavailable
		}
		return ctx, func() { <-s.gate; s.pending.Add(-1); cancel() }, nil
	case <-ctx.Done():
		s.pending.Add(-1)
		cancel()
		return ctx, func() {}, ctx.Err()
	}
}

func (s *SQLiteStore) capacity() error {
	free, err := availableBytes(s.dir)
	if err != nil {
		return agent.ErrStoreUnavailable
	}
	if free < s.options.MinFreeBytes {
		return agent.ErrCapacity
	}
	var total int64
	for _, name := range []string{databaseName, databaseName + "-wal", databaseName + "-shm"} {
		info, err := os.Stat(filepath.Join(s.dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return agent.ErrStoreUnavailable
		}
		total += info.Size()
	}
	if total >= s.options.MaxJournalBytes {
		return agent.ErrCapacity
	}
	return nil
}

func (s *SQLiteStore) write(ctx context.Context, requireReady, newWork bool, fn func(context.Context, *sql.Tx) error, after ...func()) error {
	return s.transaction(ctx, requireReady, newWork, false, fn, after...)
}

func (s *SQLiteStore) transaction(ctx context.Context, requireReady, newWork, allowUncertain bool, fn func(context.Context, *sql.Tx) error, after ...func()) error {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	return s.transactionOwned(ctx, requireReady, newWork, allowUncertain, fn, after...)
}

// transactionOwned requires the operation gate. Receipt replay uses that same
// owner to decide atomically between a read-only replay and new admission.
func (s *SQLiteStore) transactionOwned(ctx context.Context, requireReady, newWork, allowUncertain bool, fn func(context.Context, *sql.Tx) error, after ...func()) error {
	var err error
	if s.failed.Load() {
		return agent.ErrStoreUnavailable
	}
	if s.anchorUncertain && !allowUncertain {
		return agent.ErrRecoveryRequired
	}
	if requireReady && !s.reconciled() {
		return agent.ErrRecoveryRequired
	}
	if err = s.checkFiles(); err != nil {
		s.failed.Store(true)
		return agent.ErrStoreUnavailable
	}
	if newWork {
		if _, err = s.launchStatus(ctx, s.db); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.failed.Store(true)
		return agent.ErrStoreUnavailable
	}
	defer tx.Rollback()
	if err = fn(ctx, tx); err != nil {
		if !isDomainError(err) {
			s.failed.Store(true)
			return agent.ErrStoreUnavailable
		}
		return err
	}
	if s.anchor.Revision == math.MaxInt64 {
		s.failed.Store(true)
		return agent.ErrStoreUnavailable
	}
	if _, err = tx.ExecContext(ctx, "UPDATE metadata SET revision=revision+1 WHERE singleton=1"); err == nil && s.fault != nil {
		err = s.fault("before-commit")
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.failed.Store(true)
		return agent.ErrStoreUnavailable
	}
	s.anchor.Revision++
	if s.fault != nil {
		if err = s.fault("after-commit"); err != nil {
			s.failed.Store(true)
			return agent.ErrStoreUnavailable
		}
	}
	if err = s.writeAnchor(); err != nil {
		s.failed.Store(true)
		return agent.ErrStoreUnavailable
	}
	s.anchorUncertain = false
	if s.fault != nil {
		if err = s.fault("after-anchor"); err != nil {
			s.failed.Store(true)
			return agent.ErrStoreUnavailable
		}
	}
	for _, apply := range after {
		apply()
	}
	return nil
}

func isDomainError(err error) bool {
	return errors.Is(err, agent.ErrConflict) || errors.Is(err, agent.ErrNotFound) || errors.Is(err, agent.ErrCapacity) || errors.Is(err, agent.ErrRecoveryRequired) || errors.Is(err, agent.ErrMaintenance)
}

func validScope(v agent.StoreScope) bool {
	return validID(v.InstallationID) && validID(v.TenantID) && validID(v.HostID) && validID(v.EndpointIdentity) && validCounter(v.SessionEpoch, false)
}
func validID(s string) bool { return len(s) > 0 && len(s) <= 256 }
func validCounter(s string, zero bool) bool {
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && strconv.FormatUint(n, 10) == s && (zero || n > 0)
}
func padded(s string) string { return fmt.Sprintf("%020s", s) }
func unpad(s string) string  { n, _ := strconv.ParseUint(s, 10, 64); return strconv.FormatUint(n, 10) }

func (s *SQLiteStore) requireScope(scope agent.StoreScope) error {
	if !s.sessionReady {
		return agent.ErrRecoveryRequired
	}
	if scope != s.scope || !validScope(scope) {
		return agent.ErrConflict
	}
	return nil
}

func (s *SQLiteStore) reconciled() bool {
	return s.ready && s.reconciledGeneration == s.runtimeGeneration.Load() && fresh(s.inventoryObservedAt)
}

func (s *SQLiteStore) Health(ctx context.Context) agent.StoreHealth {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return agent.StoreHealth{Reason: "unavailable"}
	}
	defer release()
	h := agent.StoreHealth{JournalID: s.anchor.JournalID, Revision: strconv.FormatInt(s.anchor.Revision, 10), Reason: "reconciliation-required"}
	h.Reason, err = s.launchStatus(ctx, s.db)
	h.Ready = err == nil
	return h
}

// launchStatus is called under the operation owner by diagnostics, new-work
// transactions and the final creation fence. Recovery writes use separate gates.
func (s *SQLiteStore) launchStatus(ctx context.Context, reader stateReader) (string, error) {
	if s.failed.Load() {
		return "unavailable", agent.ErrStoreUnavailable
	}
	if s.anchorUncertain {
		return "anchor-reconciliation-required", agent.ErrRecoveryRequired
	}
	if s.maintenance.Load() {
		return "maintenance", agent.ErrMaintenance
	}
	if err := s.checkFiles(); err != nil {
		return "unavailable", agent.ErrStoreUnavailable
	}
	if err := s.capacity(); err != nil {
		return "storage-pressure", err
	}
	var count int
	var size int64
	if err := reader.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(length(payload)),0) FROM outbox_events WHERE payload IS NOT NULL").Scan(&count, &size); err != nil {
		return "unavailable", agent.ErrStoreUnavailable
	}
	if count >= s.options.MaxOutboxEvents || size >= s.options.MaxOutboxBytes {
		return "outbox-pressure", agent.ErrCapacity
	}
	var recovery int
	if err := reader.QueryRowContext(ctx, "SELECT count(*) FROM peer_recovery_approvals WHERE completed=0 AND superseded=0").Scan(&recovery); err != nil {
		return "unavailable", agent.ErrStoreUnavailable
	}
	if recovery != 0 {
		return "operator-recovery", agent.ErrRecoveryRequired
	}
	if s.reconciled() {
		if s.options.ReservationLimits == (agent.ReservationLimits{}) {
			return "reservation-limits-required", agent.ErrCapacity
		}
		if _, err := s.remainingReservations(ctx, reader); err != nil {
			return "reservation-pressure", err
		}
		return "ready", nil
	}
	return "reconciliation-required", agent.ErrRecoveryRequired
}

func (s *SQLiteStore) Close() error {
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	s.gate <- struct{}{}
	defer func() { <-s.gate }()
	if s.closed {
		return nil
	}
	s.closed = true
	return errors.Join(s.db.Close(), s.fences.Close())
}
