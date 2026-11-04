package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"

	"github.com/Neticora/neticora-docker-runnerd/agent"
)

func budget(raw []byte) ([4]uint64, error) {
	var doc struct {
		CPU     string `json:"cpuMillis"`
		Memory  string `json:"memoryBytes"`
		Storage string `json:"storageBytes"`
		Slots   string `json:"slots"`
	}
	var out [4]uint64
	if err := json.Unmarshal(raw, &doc); err != nil {
		return out, err
	}
	for i, v := range []string{doc.CPU, doc.Memory, doc.Storage, doc.Slots} {
		if !validCounter(v, false) {
			return out, agent.ErrConflict
		}
		n, _ := strconv.ParseUint(v, 10, 64)
		out[i] = n
	}
	return out, nil
}

type stateReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// Account for every unresolved physical attempt. Subtraction avoids uint64
// overflow both in launch diagnostics and inside the reservation transaction.
func (s *SQLiteStore) remainingReservations(ctx context.Context, reader stateReader) ([4]uint64, error) {
	limits := s.options.ReservationLimits
	remaining := [4]uint64{limits.CPUMillis, limits.MemoryBytes, limits.StorageBytes, limits.Slots}
	rows, err := reader.QueryContext(ctx, "SELECT resources FROM reservations WHERE released=0")
	if err != nil {
		return remaining, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return remaining, err
		}
		used, e := budget(raw)
		if e != nil {
			return remaining, e
		}
		for i, n := range used {
			if n > remaining[i] {
				return remaining, agent.ErrCapacity
			}
			remaining[i] -= n
		}
	}
	if err = rows.Err(); err != nil {
		return remaining, err
	}
	return remaining, nil
}

func (s *SQLiteStore) reserve(ctx context.Context, tx *sql.Tx, requested []byte) error {
	want, err := budget(requested)
	if err != nil {
		return err
	}
	remaining, err := s.remainingReservations(ctx, tx)
	if err != nil {
		return err
	}
	for i, n := range want {
		if n > remaining[i] {
			return agent.ErrCapacity
		}
	}
	return nil
}
