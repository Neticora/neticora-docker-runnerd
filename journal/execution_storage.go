package journal

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/Neticora/neticora-docker-runnerd/agent"
)

// StorageIdentity pins durable filesystem/inode identity. Mount crossings are
// rejected on every fd-relative open; mount IDs are not durable across systemd
// service mount-namespace recreation.
type StorageIdentity struct{ Device, Inode uint64 }

// ExecutionStorage is protected journal data. No resource path comes from a job.
// Disposed rows remain permanent fences; their names are never allocated again.
type ExecutionStorage struct {
	Identity          agent.Identity
	Endpoint          string
	Root              string
	Name              string
	RootIdentity      StorageIdentity
	DirectoryIdentity StorageIdentity
	State             string
}

// StorageIntent must commit before mkdir. Existing rows must match exactly;
// neither a retry nor a new boot/endpoint is authority to allocate a replacement.
func (s *SQLiteStore) StorageIntent(ctx context.Context, scope agent.StoreScope, r ExecutionStorage) (ExecutionStorage, error) {
	if r.State != "intent" || r.RootIdentity.Inode == 0 || r.DirectoryIdentity != (StorageIdentity{}) || !filepath.IsAbs(r.Root) || filepath.Clean(r.Root) != r.Root || filepath.Base(r.Name) != r.Name || len(r.Name) != 68 || r.Name[:4] != "nrd-" {
		return r, agent.ErrConflict
	}
	raw, _ := json.Marshal(r)
	err := s.write(ctx, true, true, func(ctx context.Context, tx *sql.Tx) error {
		if err := s.requireScope(scope); err != nil {
			return err
		}
		var identity, command []byte
		var endpoint, state string
		if err := tx.QueryRowContext(ctx, "SELECT identity,command,endpoint_identity,state FROM executions WHERE execution_id=? AND generation=?", r.Identity.ExecutionID, r.Identity.Generation).Scan(&identity, &command, &endpoint, &state); err != nil {
			return agent.ErrConflict
		}
		var id agent.Identity
		var start struct {
			Spec struct {
				Template string `json:"templateVersion"`
			}
		}
		if json.Unmarshal(identity, &id) != nil || id != r.Identity || json.Unmarshal(command, &start) != nil || start.Spec.Template != "linux-github-disk-v1" || endpoint != r.Endpoint || scope.EndpointIdentity != endpoint || id.InstallationID != scope.InstallationID || state == "cleaned" {
			return agent.ErrConflict
		}
		var previous []byte
		err := tx.QueryRowContext(ctx, "SELECT record FROM execution_storage WHERE execution_id=? AND generation=?", id.ExecutionID, id.Generation).Scan(&previous)
		if err == nil {
			var old ExecutionStorage
			if json.Unmarshal(previous, &old) != nil {
				return agent.ErrConflict
			}
			test := old
			test.State = "intent"
			test.DirectoryIdentity = StorageIdentity{}
			testRaw, _ := json.Marshal(test)
			if !bytes.Equal(testRaw, raw) {
				return agent.ErrConflict
			}
			r = old
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO execution_storage(execution_id,generation,record,state) VALUES(?,?,?,?)", id.ExecutionID, id.Generation, raw, r.State)
		return err
	})
	return r, err
}

func (s *SQLiteStore) StorageTransition(ctx context.Context, scope agent.StoreScope, old, next ExecutionStorage) error {
	same := next
	same.State = old.State
	same.DirectoryIdentity = old.DirectoryIdentity
	if same != old || !((old.State == "intent" && next.State == "allocated" && next.DirectoryIdentity.Inode != 0) || (old.State == "allocated" && next.State == "retiring" && next.DirectoryIdentity == old.DirectoryIdentity) || (old.State == "intent" && next.State == "retiring" && next.DirectoryIdentity == (StorageIdentity{})) || (old.State == "retiring" && next.State == "disposed" && next.DirectoryIdentity == old.DirectoryIdentity)) {
		return agent.ErrConflict
	}
	before, _ := json.Marshal(old)
	after, _ := json.Marshal(next)
	return s.write(ctx, false, false, func(ctx context.Context, tx *sql.Tx) error {
		if err := s.requireScope(scope); err != nil {
			return err
		}
		if scope.EndpointIdentity != old.Endpoint {
			return agent.ErrRecoveryRequired
		}
		result, err := tx.ExecContext(ctx, "UPDATE execution_storage SET record=?,state=? WHERE execution_id=? AND generation=? AND record=? AND state=?", after, next.State, old.Identity.ExecutionID, old.Identity.Generation, before, old.State)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return agent.ErrConflict
		}
		return nil
	})
}

func (s *SQLiteStore) StorageRecords(ctx context.Context) ([]ExecutionStorage, error) {
	return s.storageRecords(ctx, false)
}

// StoragePendingRecords bounds only outstanding obligations; permanent disposed
// fences do not exhaust the active directory reconciliation scan.
func (s *SQLiteStore) StoragePendingRecords(ctx context.Context) ([]ExecutionStorage, error) {
	return s.storageRecords(ctx, true)
}
func (s *SQLiteStore) storageRecords(ctx context.Context, pending bool) ([]ExecutionStorage, error) {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if s.failed.Load() {
		return nil, agent.ErrStoreUnavailable
	}
	query := "SELECT record FROM execution_storage"
	if pending {
		query += " WHERE state<>'disposed'"
	}
	query += " ORDER BY execution_id,generation LIMIT 10001"
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, agent.ErrStoreUnavailable
	}
	defer rows.Close()
	out := []ExecutionStorage{}
	for rows.Next() {
		var raw []byte
		var r ExecutionStorage
		if rows.Scan(&raw) != nil || json.Unmarshal(raw, &r) != nil {
			return nil, agent.ErrStoreUnavailable
		}
		out = append(out, r)
	}
	if len(out) > 10000 {
		return nil, agent.ErrCapacity
	}
	return out, rows.Err()
}

func storageDisposed(ctx context.Context, tx *sql.Tx, id, generation string) error {
	var command []byte
	if err := tx.QueryRowContext(ctx, "SELECT command FROM executions WHERE execution_id=? AND generation=?", id, generation).Scan(&command); err != nil {
		return err
	}
	var start struct {
		Spec struct {
			Template string `json:"templateVersion"`
		}
	}
	if json.Unmarshal(command, &start) != nil {
		return agent.ErrConflict
	}
	if start.Spec.Template != "linux-github-disk-v1" {
		return nil
	}
	var state string
	err := tx.QueryRowContext(ctx, "SELECT state FROM execution_storage WHERE execution_id=? AND generation=?", id, generation).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return agent.ErrRecoveryRequired
	}
	if err != nil {
		return err
	}
	if state != "disposed" {
		return agent.ErrRecoveryRequired
	}
	return nil
}

// StorageRecord resolves the original immutable identity without scanning retired history.
func (s *SQLiteStore) StorageRecord(ctx context.Context, id agent.Identity) (ExecutionStorage, error) {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return ExecutionStorage{}, err
	}
	defer release()
	if s.failed.Load() {
		return ExecutionStorage{}, agent.ErrStoreUnavailable
	}
	var raw []byte
	err = s.db.QueryRowContext(ctx, "SELECT record FROM execution_storage WHERE execution_id=? AND generation=?", id.ExecutionID, id.Generation).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ExecutionStorage{}, agent.ErrNotFound
	}
	if err != nil {
		return ExecutionStorage{}, agent.ErrStoreUnavailable
	}
	var r ExecutionStorage
	if json.Unmarshal(raw, &r) != nil || r.Identity != id {
		return r, agent.ErrConflict
	}
	return r, nil
}
