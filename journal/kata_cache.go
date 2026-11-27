package journal

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
)

// KataCacheVolume is the durable binding from an admitted attempt to a thin
// LV. The name is chosen before LVM is called. Once observed, its UUID is fixed.
type KataCacheVolume struct {
	ExecutionID, Generation, Key, Name string
	ParentUUID, UUID, FilesystemUUID   string
	State                              string
	CleanExitAt                        int64
}

const kataCacheColumns = "execution_id,generation,cache_key,name,parent_uuid,uuid,filesystem_uuid,state,clean_exit_at"

type cacheScanner interface{ Scan(...any) error }

func scanKataCache(row cacheScanner) (KataCacheVolume, error) {
	var v KataCacheVolume
	err := row.Scan(&v.ExecutionID, &v.Generation, &v.Key, &v.Name, &v.ParentUUID, &v.UUID, &v.FilesystemUUID, &v.State, &v.CleanExitAt)
	return v, err
}

func (s *SQLiteStore) kataCacheRead(ctx context.Context, requireSession bool, query string, args ...any) (KataCacheVolume, bool, error) {
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return KataCacheVolume{}, false, err
	}
	defer release()
	if s.failed.Load() || (requireSession && (!s.sessionReady || s.anchorUncertain)) {
		return KataCacheVolume{}, false, agent.ErrRecoveryRequired
	}
	if err = s.checkFiles(); err != nil {
		return KataCacheVolume{}, false, agent.ErrStoreUnavailable
	}
	v, err := scanKataCache(s.db.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return KataCacheVolume{}, false, nil
	}
	if err != nil {
		return KataCacheVolume{}, false, agent.ErrStoreUnavailable
	}
	return v, true, nil
}

func (s *SQLiteStore) KataCacheAttempt(ctx context.Context, cursor agent.ExecutionCursor) (KataCacheVolume, bool, error) {
	return s.kataCacheRead(ctx, false, "SELECT "+kataCacheColumns+" FROM kata_cache_volumes WHERE execution_id=? AND generation=?", cursor.ExecutionID, cursor.Generation)
}

func (s *SQLiteStore) KataCacheHead(ctx context.Context, key string) (KataCacheVolume, bool, error) {
	return s.kataCacheRead(ctx, true, "SELECT "+kataCacheColumns+" FROM kata_cache_volumes WHERE cache_key=? AND uuid=(SELECT uuid FROM kata_cache_heads WHERE cache_key=?) AND state='retained'", key, key)
}

func (s *SQLiteStore) BeginKataCache(ctx context.Context, scope agent.StoreScope, cursor agent.ExecutionCursor, key, name string, cold bool) error {
	return s.write(ctx, true, true, func(ctx context.Context, tx *sql.Tx) error {
		if s.scope != scope || !validID(cursor.ExecutionID) || !validCounter(cursor.Generation, false) || key == "" || name == "" {
			return agent.ErrConflict
		}
		var allowed int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM executions e JOIN reservations r
		    USING (execution_id,generation) WHERE e.execution_id=? AND e.generation=? AND
		    e.state IN ('accepted','prepared') AND e.cleanup_pending=0 AND r.released=0)`,
			cursor.ExecutionID, cursor.Generation).Scan(&allowed); err != nil {
			return err
		}
		if allowed != 1 {
			return agent.ErrConflict
		}
		state := "preparing"
		if cold {
			state = "cold"
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO kata_cache_volumes(execution_id,generation,cache_key,name,parent_uuid,state)
		    VALUES(?,?,?,?,COALESCE((SELECT uuid FROM kata_cache_heads WHERE cache_key=?),''),?)
		    ON CONFLICT (execution_id,generation) DO NOTHING`, cursor.ExecutionID, cursor.Generation, key, name, key, state)
		return err
	})
}

// ColdKataCache fixes a fallback for an allocation that never became ready.
// The caller first removes any partially created owned LV.
func (s *SQLiteStore) ColdKataCache(ctx context.Context, v KataCacheVolume) error {
	return s.write(ctx, true, false, func(ctx context.Context, tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, "UPDATE kata_cache_volumes SET state='cold' WHERE name=? AND cache_key=? AND state='preparing'", v.Name, v.Key)
		return cacheUpdate(result, err)
	})
}

func (s *SQLiteStore) ReadyKataCache(ctx context.Context, v KataCacheVolume, uuid, filesystemUUID string) error {
	if uuid == "" || filesystemUUID == "" {
		return agent.ErrConflict
	}
	return s.write(ctx, true, false, func(ctx context.Context, tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE kata_cache_volumes SET uuid=?,filesystem_uuid=?,state='ready'
		    WHERE name=? AND cache_key=? AND (state='preparing' OR (state='ready' AND uuid=? AND filesystem_uuid=?))`,
			uuid, filesystemUUID, v.Name, v.Key, uuid, filesystemUUID)
		return cacheUpdate(result, err)
	})
}

// MarkKataCacheCleanExit records the successful Docker observation before
// removal makes it unavailable. A retry after Remove can resume the decision.
func (s *SQLiteStore) MarkKataCacheCleanExit(ctx context.Context, v KataCacheVolume) error {
	return s.write(ctx, true, false, func(ctx context.Context, tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE kata_cache_volumes SET clean_exit_at=CASE WHEN clean_exit_at=0 THEN ? ELSE clean_exit_at END
		    WHERE name=? AND cache_key=? AND state='ready'`, time.Now().Unix(), v.Name, v.Key)
		return cacheUpdate(result, err)
	})
}

// CompleteKataCache is called only after native detachment. Publishing uses the
// parent UUID captured before allocation and cannot replace a newer generation.
func (s *SQLiteStore) CompleteKataCache(ctx context.Context, v KataCacheVolume, promote bool) error {
	return s.write(ctx, true, false, func(ctx context.Context, tx *sql.Tx) error {
		var state, parent, uuid string
		var cleanExit int64
		err := tx.QueryRowContext(ctx, `SELECT state,parent_uuid,uuid,clean_exit_at FROM kata_cache_volumes WHERE name=? AND cache_key=?`, v.Name, v.Key).Scan(&state, &parent, &uuid, &cleanExit)
		if errors.Is(err, sql.ErrNoRows) {
			return agent.ErrConflict
		}
		if err != nil || state == "retained" || state == "discard" || state == "cold" {
			return err
		}
		final := "discard"
		if promote && state == "ready" && cleanExit > 0 {
			var head string
			err = tx.QueryRowContext(ctx, "SELECT uuid FROM kata_cache_heads WHERE cache_key=?", v.Key).Scan(&head)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if head == parent {
				if _, err = tx.ExecContext(ctx, `INSERT INTO kata_cache_heads(cache_key,uuid) VALUES(?,?)
				    ON CONFLICT(cache_key) DO UPDATE SET uuid=excluded.uuid`, v.Key, uuid); err != nil {
					return err
				}
				final = "retained"
			}
		}
		_, err = tx.ExecContext(ctx, "UPDATE kata_cache_volumes SET state=? WHERE name=?", final, v.Name)
		return err
	})
}

// KataCacheGarbage returns discarded attempts and generations beyond the
// retained history. A head or the origin of an unfinished allocation stays pinned.
func (s *SQLiteStore) KataCacheGarbage(ctx context.Context, key string, retained int) ([]KataCacheVolume, error) {
	if retained < 1 {
		return nil, agent.ErrConflict
	}
	ctx, release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if s.failed.Load() || !s.sessionReady || s.anchorUncertain {
		return nil, agent.ErrRecoveryRequired
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+kataCacheColumns+` FROM kata_cache_volumes
	    WHERE cache_key=? AND (state='discard' OR (state='retained' AND
	    uuid<>(SELECT uuid FROM kata_cache_heads WHERE cache_key=?) AND
	    uuid NOT IN (SELECT uuid FROM kata_cache_volumes WHERE cache_key=? AND state='retained' ORDER BY rowid DESC LIMIT ?) AND
	    uuid NOT IN (SELECT parent_uuid FROM kata_cache_volumes WHERE cache_key=? AND state='preparing')))
	    ORDER BY rowid LIMIT 64`, key, key, key, retained, key)
	if err != nil {
		return nil, agent.ErrStoreUnavailable
	}
	defer rows.Close()
	var volumes []KataCacheVolume
	for rows.Next() {
		v, err := scanKataCache(rows)
		if err != nil {
			return nil, agent.ErrStoreUnavailable
		}
		volumes = append(volumes, v)
	}
	return volumes, rows.Err()
}

func (s *SQLiteStore) ForgetKataCache(ctx context.Context, v KataCacheVolume) error {
	return s.write(ctx, true, false, func(ctx context.Context, tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM kata_cache_volumes WHERE name=? AND cache_key=?
		    AND state IN ('discard','retained') AND uuid NOT IN (SELECT uuid FROM kata_cache_heads)
		    AND (state='discard' OR uuid NOT IN (SELECT parent_uuid FROM kata_cache_volumes WHERE state='preparing'))`, v.Name, v.Key)
		return cacheUpdate(result, err)
	})
}

// ForgetRecoveredKataCache discards only uncommitted cache owned by the
// independently approved interrupted execution. No recovery path publishes.
func (s *SQLiteStore) ForgetRecoveredKataCache(ctx context.Context, a *peerrecovery.Authorization, v KataCacheVolume) error {
	if err := s.CheckPeerRecoveryMutation(ctx, a, v.ExecutionID, v.Generation); err != nil {
		return err
	}
	return s.write(ctx, false, false, func(ctx context.Context, tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM kata_cache_volumes
		    WHERE execution_id=? AND generation=? AND name=? AND cache_key=?
		    AND state IN ('preparing','ready','discard','cold') AND uuid NOT IN (SELECT uuid FROM kata_cache_heads)`,
			v.ExecutionID, v.Generation, v.Name, v.Key)
		return cacheUpdate(result, err)
	})
}

func cacheUpdate(result sql.Result, err error) error {
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
}
