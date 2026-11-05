package journal

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"modernc.org/sqlite"
)

type CheckpointResult struct{ Busy, LogFrames, CheckpointedFrames int }

func (s *SQLiteStore) beginMaintenance(ctx context.Context) (context.Context, func(), error) {
	if !s.maintenanceMu.TryLock() {
		return ctx, func() {}, agent.ErrMaintenance
	}
	ctx, cancel := context.WithTimeout(ctx, s.options.MaintenanceTimeout)
	return ctx, func() { s.maintenance.Store(false); s.maintenanceMu.Unlock(); cancel() }, nil
}

func (s *SQLiteStore) maintenanceConnection(mode string, busyMillis string) (*sql.DB, error) {
	u := url.URL{Scheme: "file", Path: filepath.Join(s.dir, databaseName)}
	u.RawQuery = url.Values{"mode": {mode}, "_pragma": {"busy_timeout(" + busyMillis + ")", "synchronous(FULL)", "foreign_keys(ON)", "temp_store(MEMORY)"}}.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

// Checkpoint reclaims WAL space without deleting commands, event identities,
// creation fences or unacknowledged payloads. Busy is returned to the caller.
func (s *SQLiteStore) Checkpoint(ctx context.Context) (out CheckpointResult, err error) {
	ctx, finish, err := s.beginMaintenance(ctx)
	if err != nil {
		return out, err
	}
	defer finish()
	_, release, err := s.acquireWithin(ctx, s.options.MaintenanceTimeout)
	if err != nil {
		return out, err
	}
	s.maintenance.Store(true)
	if s.failed.Load() {
		release()
		return out, agent.ErrStoreUnavailable
	}
	err = s.checkFiles()
	release()
	if err != nil {
		return out, agent.ErrStoreUnavailable
	}
	db, err := s.maintenanceConnection("rw", "0")
	if err != nil {
		return out, err
	}
	defer db.Close()
	// A separate connection with no busy wait reports contention immediately.
	// Normal receipt/event operations keep their own connection and deadlines.
	err = db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&out.Busy, &out.LogFrames, &out.CheckpointedFrames)
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		s.failed.Store(true)
		return out, agent.ErrStoreUnavailable
	}
	return out, nil
}

// Backup includes committed WAL data through SQLite's online backup API. The
// output is a private standalone database and manifest in the protected state
// directory. Its pinned read snapshot permits ordinary recovery writes during
// copying. New launch admission pauses until maintenance finishes.
func (s *SQLiteStore) Backup(ctx context.Context, name string) error {
	if !safeBackupName(name) {
		return agent.ErrConflict
	}
	ctx, finish, err := s.beginMaintenance(ctx)
	if err != nil {
		return err
	}
	defer finish()
	_, release, err := s.acquireWithin(ctx, s.options.MaintenanceTimeout)
	if err != nil {
		return err
	}
	s.maintenance.Store(true)
	gateHeld := true
	defer func() {
		if gateHeld {
			release()
		}
	}()
	if s.failed.Load() {
		return agent.ErrStoreUnavailable
	}
	if err = s.capacity(); err != nil {
		return err
	}
	if err = s.checkFiles(); err != nil {
		return agent.ErrStoreUnavailable
	}
	source, err := s.maintenanceConnection("ro", "5000")
	if err != nil {
		return err
	}
	defer source.Close()
	conn, err := source.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN"); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	manifest := backupManifest{Fences: make(map[string]json.RawMessage)}
	var scopeRaw []byte
	// The first read pins the WAL snapshot while the operation owner excludes
	// concurrent commits and creation-marker writes. Its revision, not a later
	// live anchor, must accompany the copied database.
	if err = conn.QueryRowContext(ctx, "SELECT journal_id,revision,scope FROM metadata WHERE singleton=1").Scan(&manifest.Anchor.JournalID, &manifest.Anchor.Revision, &scopeRaw); err != nil {
		return err
	}
	if manifest.Anchor != s.anchor {
		return agent.ErrRecoveryRequired
	}
	if len(scopeRaw) > 0 {
		if err = json.Unmarshal(scopeRaw, &manifest.Scope); err != nil {
			return err
		}
	} else {
		manifest.Scope.SessionEpoch = "0"
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var pages, pageSize uint64
	if err = conn.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return err
	}
	if err = conn.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return err
	}
	free, err := availableBytes(s.dir)
	if err != nil {
		return err
	}
	if free < s.options.MinFreeBytes || pageSize == 0 || pages > (free-s.options.MinFreeBytes)/pageSize {
		return agent.ErrCapacity
	}
	path := filepath.Join(s.dir, name)
	if err = privateFile(path, true); err != nil {
		return err
	}
	// Permanent marker contents are immutable. Read the captured filenames
	// outside the operation gate, alongside the potentially long backup copy.
	release()
	gateHeld = false
	if s.fault != nil {
		if err = s.fault("backup-snapshot"); err != nil {
			return err
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	err = conn.Raw(func(raw any) error {
		source, ok := raw.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return agent.ErrStoreUnavailable
		}
		backup, err := source.NewBackup(path)
		if err != nil {
			return err
		}
		finished := false
		defer func() {
			if !finished {
				_ = backup.Finish()
			}
		}()
		for {
			if err = ctx.Err(); err != nil {
				return err
			}
			free, e := availableBytes(s.dir)
			if e != nil {
				return e
			}
			if free < s.options.MinFreeBytes || free-s.options.MinFreeBytes < 128*pageSize+(1<<20) {
				return agent.ErrCapacity
			}
			more, e := backup.Step(128)
			if e != nil {
				return e
			}
			if !more {
				break
			}
		}
		finished = true
		return backup.Finish()
	})
	if err != nil {
		return err
	}
	if err = privateFile(path, false); err != nil {
		return err
	}
	// The snapshot has been copied; release its WAL reader before hashing/sync.
	if _, err = conn.ExecContext(ctx, "ROLLBACK"); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	digest, err := fileDigestContext(ctx, path)
	if err != nil {
		return err
	}
	manifest.Digest = digest
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return err
		}
		if !strings.HasSuffix(entry.Name(), ".creation.json") {
			continue
		}
		if len(manifest.Fences) >= 10000 {
			return agent.ErrCapacity
		}
		raw, e := hostfs.ReadPrivate(filepath.Join(s.dir, entry.Name()), 8192)
		if e != nil {
			return e
		}
		var marker record
		if e = json.Unmarshal(raw, &marker); e != nil {
			return agent.ErrRecoveryRequired
		}
		manifest.Fences[entry.Name()] = json.RawMessage(raw)
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if s.failed.Load() {
		return agent.ErrStoreUnavailable
	}
	raw, _ := json.Marshal(manifest)
	if len(raw) > 16<<20 {
		return agent.ErrCapacity
	}
	f, err = s.fences.root.OpenFile(name+".json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err == nil {
		err = syncDirectory(s.dir)
	}
	return err
}

type backupManifest struct {
	Anchor anchor                     `json:"anchor"`
	Digest string                     `json:"sha256"`
	Fences map[string]json.RawMessage `json:"creationFences"`
	Scope  agent.StoreScope           `json:"scope"`
}

func safeBackupName(name string) bool {
	return len(name) <= 100 && strings.HasPrefix(name, "backup-") && strings.HasSuffix(name, ".db") && filepath.Base(name) == name && !strings.ContainsAny(name, "\\\x00")
}
func fileDigest(path string) (string, error) {
	return fileDigestContext(context.Background(), path)
}

func fileDigestContext(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 64<<10)
	for {
		if err = ctx.Err(); err != nil {
			return "", err
		}
		n, e := f.Read(buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RestoreBackup only restores into an empty, separately provisioned state
// directory. It never overwrites an installation. The snapshot includes its
// permanent creation fences. A restored store still requires a NEW host session
// authoritative reconciliation; copying both database and anchor cannot prove
// freshness. Operators must fence old processes and recover ownership first.
func RestoreBackup(ctx context.Context, sourceDir, name, destinationDir string) error {
	if !safeBackupName(name) || sourceDir == destinationDir {
		return agent.ErrConflict
	}
	source, err := Open(sourceDir)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := Open(destinationDir)
	if err != nil {
		return err
	}
	defer destination.Close()
	if err = localStorage(destinationDir); err != nil {
		return err
	}
	entries, err := os.ReadDir(destinationDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != "instance.lock" {
			return agent.ErrConflict
		}
	}
	manifestRaw, err := hostfs.ReadPrivate(filepath.Join(sourceDir, name+".json"), 16<<20)
	if err != nil {
		return err
	}
	var manifest backupManifest
	if err = json.Unmarshal(manifestRaw, &manifest); err != nil || manifest.Anchor.JournalID == "" || manifest.Anchor.Revision < 0 {
		return agent.ErrRecoveryRequired
	}
	path := filepath.Join(sourceDir, name)
	if err = privateFile(path, false); err != nil {
		return err
	}
	digest, err := fileDigest(path)
	if err != nil {
		return err
	}
	if digest != manifest.Digest {
		return agent.ErrRecoveryRequired
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	in, err := source.root.Open(name)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := destination.root.OpenFile(databaseName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if e := out.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	for name, raw := range manifest.Fences {
		if filepath.Base(name) != name || strings.ContainsAny(name, "\\\x00") || !strings.HasSuffix(name, ".creation.json") || len(raw) > 8192 {
			return agent.ErrRecoveryRequired
		}
		f, e := destination.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(raw)
		if e == nil {
			e = f.Sync()
		}
		if closeErr := f.Close(); e == nil {
			e = closeErr
		}
		if e != nil {
			return e
		}
	}
	marker, err := destination.root.OpenFile("recovery.restored.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	restoredRaw, _ := json.Marshal(manifest.Scope)
	_, err = marker.Write(restoredRaw)
	if err == nil {
		err = marker.Sync()
	}
	if e := marker.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	s := &SQLiteStore{fences: destination, dir: destinationDir, anchor: manifest.Anchor}
	return s.writeAnchor()
}

// Creation fences share the SQLite installation owner. A stable start intent

// CheckLaunch rechecks committed cancellation, original session, expiry and
// capacity immediately before starting a created object. It cannot create a new
// creation claim or authorize restart of an exited execution.
func (s *SQLiteStore) CheckLaunch(ctx context.Context, start []byte, a Authority) error {
	var doc commandDocument
	canonical, err := snapshot("StartCommand", start, &doc)
	if err != nil {
		return err
	}
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	if _, err = s.launchStatus(ctx, s.db); err != nil {
		return err
	}
	if a.TenantID != s.scope.TenantID || a.HostID != s.scope.HostID || a.SessionEpoch != s.scope.SessionEpoch || a.EndpointIdentity != s.scope.EndpointIdentity {
		return agent.ErrConflict
	}
	var stored []byte
	var epoch, endpoint, state string
	var blocked int
	err = s.db.QueryRowContext(ctx, `SELECT e.command,e.session_epoch,e.endpoint_identity,e.state,
 (SELECT count(*) FROM commands c WHERE c.execution_id=e.execution_id AND c.generation=e.generation AND c.kind<>'start')
 FROM executions e JOIN start_intents i USING(execution_id,generation) WHERE e.command_id=?`, doc.CommandID).Scan(&stored, &epoch, &endpoint, &state, &blocked)
	if err != nil || !equalBytes(stored, canonical) || epoch != a.SessionEpoch || endpoint != a.EndpointIdentity || blocked != 0 || (state != "accepted" && state != "prepared") || !doc.Spec.AuthorizationExpiresAt.After(time.Now()) {
		return agent.ErrConflict
	}
	return nil
}

// A stable start intent
// must already exist. This still only claims a boundary, never starts a runtime.
func (s *SQLiteStore) ClaimCreation(ctx context.Context, start []byte, a Authority) error {
	var doc commandDocument
	canonical, err := snapshot("StartCommand", start, &doc)
	if err != nil {
		return err
	}
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	if _, err = s.launchStatus(ctx, s.db); err != nil {
		return err
	}
	if a.TenantID != s.scope.TenantID || a.HostID != s.scope.HostID || a.SessionEpoch != s.scope.SessionEpoch || a.EndpointIdentity != s.scope.EndpointIdentity {
		return agent.ErrConflict
	}
	var stored []byte
	var epoch, endpoint string
	var blocked int
	err = s.db.QueryRowContext(ctx, `SELECT e.command,e.session_epoch,e.endpoint_identity,
	  (SELECT count(*) FROM commands c WHERE c.execution_id=e.execution_id AND c.generation=e.generation AND c.kind<>'start')
	  FROM executions e JOIN start_intents i USING(execution_id,generation)
	  WHERE e.command_id=? AND e.state='accepted'`, doc.CommandID).Scan(&stored, &epoch, &endpoint, &blocked)
	if err != nil || !equalBytes(stored, canonical) || epoch != a.SessionEpoch || endpoint != a.EndpointIdentity || blocked != 0 {
		return agent.ErrConflict
	}
	if !doc.Spec.AuthorizationExpiresAt.After(time.Now()) {
		return agent.ErrConflict
	}
	return s.fences.ClaimCreation(canonical, a)
}
func equalBytes(a, b []byte) bool { return string(a) == string(b) }

// VerifyCreationClaim is read-only recovery evidence, usable before session
// reconciliation. Matching container labels do not replace the durable claim.
// It accepts an older original session for observation, never for fresh launch.
func (s *SQLiteStore) VerifyCreationClaim(ctx context.Context, scope agent.StoreScope, startRaw []byte) error {
	var doc commandDocument
	canonical, e := snapshot("StartCommand", startRaw, &doc)
	if e != nil {
		return e
	}
	ctx, release, e := s.acquire(ctx)
	if e != nil {
		return e
	}
	defer release()
	if s.failed.Load() {
		return agent.ErrStoreUnavailable
	}
	if e = s.checkFiles(); e != nil {
		return agent.ErrStoreUnavailable
	}
	var identityRaw, stored []byte
	var epoch, endpoint string
	e = s.db.QueryRowContext(ctx, "SELECT identity,command,session_epoch,endpoint_identity FROM executions WHERE command_id=?", doc.CommandID).Scan(&identityRaw, &stored, &epoch, &endpoint)
	if e != nil {
		return s.receiptReadFailure(ctx, e)
	}
	var id agent.Identity
	if json.Unmarshal(identityRaw, &id) != nil || id.InstallationID != scope.InstallationID || id.TenantID != scope.TenantID || id.HostID != scope.HostID || id.ExecutionID != doc.Spec.ExecutionID || id.Generation != doc.Generation || id.SpecHash != doc.Spec.SpecHash || endpoint != scope.EndpointIdentity || !equalBytes(stored, canonical) {
		return agent.ErrRecoveryRequired
	}
	start, e := decode("StartCommand", canonical)
	if e != nil {
		return e
	}
	b, e := binding(start, Authority{TenantID: scope.TenantID, HostID: scope.HostID, SessionEpoch: epoch, EndpointIdentity: endpoint, KeyID: "original-creation"})
	if e != nil {
		return e
	}
	name, e := hash(map[string]string{"tenantId": scope.TenantID, "hostId": scope.HostID, "executionId": id.ExecutionID, "generation": id.Generation})
	if e != nil {
		return e
	}
	raw, e := hostfs.ReadPrivate(filepath.Join(s.dir, name+".creation.json"), 8192)
	if e != nil {
		return agent.ErrRecoveryRequired
	}
	var marker record
	if json.Unmarshal(raw, &marker) != nil || marker.State != "CREATION_CLAIMED" {
		return agent.ErrRecoveryRequired
	}
	want, e := hash(b)
	if e != nil {
		return e
	}
	actual, e := hash(marker.Binding)
	if e != nil || want != actual {
		return agent.ErrRecoveryRequired
	}
	return nil
}

// FenceNeverStarted preserves Runnerd05 proof construction under the SQLite
// installation owner. Both commands must already be durably accepted. The
// permanent file fence precedes proof return; the controller must then commit a
// HostEvent containing this proof before reporting it. Receipt is not completion.
func (s *SQLiteStore) FenceNeverStarted(ctx context.Context, start, fence []byte, a Authority, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	var startDoc, fenceDoc commandDocument
	startRaw, err := snapshot("StartCommand", start, &startDoc)
	if err != nil {
		return nil, err
	}
	fenceRaw, err := snapshot("NeverStartedCommand", fence, &fenceDoc)
	if err != nil {
		return nil, err
	}
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if !s.sessionReady || s.anchorUncertain {
		return nil, agent.ErrRecoveryRequired
	}
	if s.failed.Load() {
		return nil, agent.ErrStoreUnavailable
	}
	if a.TenantID != s.scope.TenantID || a.HostID != s.scope.HostID || a.SessionEpoch != s.scope.SessionEpoch || a.EndpointIdentity != s.scope.EndpointIdentity {
		return nil, agent.ErrConflict
	}
	var epoch, endpoint string
	if err = s.db.QueryRowContext(ctx, "SELECT session_epoch,endpoint_identity FROM executions WHERE command_id=?", startDoc.CommandID).Scan(&epoch, &endpoint); err != nil || epoch != a.SessionEpoch || endpoint != a.EndpointIdentity {
		return nil, agent.ErrConflict
	}
	for _, command := range []struct {
		id  string
		raw []byte
	}{{startDoc.CommandID, startRaw}, {fenceDoc.CommandID, fenceRaw}} {
		var stored []byte
		if err = s.db.QueryRowContext(ctx, "SELECT payload FROM commands WHERE command_id=?", command.id).Scan(&stored); err != nil || !equalBytes(stored, command.raw) {
			return nil, agent.ErrConflict
		}
	}
	if err = s.checkFiles(); err != nil {
		s.failed.Store(true)
		return nil, agent.ErrStoreUnavailable
	}
	return s.fences.FenceNeverStarted(startRaw, fenceRaw, a, key, now)
}
