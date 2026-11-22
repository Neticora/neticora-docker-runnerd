//go:build !linux

package executionstorage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

var ErrQuarantined = errors.New("execution storage requires Linux")
var ErrPressure = ErrQuarantined
var ErrCriticalPressure = ErrQuarantined

type Manager struct {
	Path  string
	Store *journal.SQLiteStore
	Scope agent.StoreScope
}

func Name(id agent.Identity) string {
	b, _ := json.Marshal(id)
	h := sha256.Sum256(b)
	return "nrd-" + hex.EncodeToString(h[:])
}
func (m Manager) Prepare(context.Context, agent.Identity) (journal.ExecutionStorage, error) {
	return journal.ExecutionStorage{}, ErrQuarantined
}
func (m Manager) Dispose(context.Context, agent.Identity) error { return ErrQuarantined }
func (m Manager) Verify(context.Context) error                  { return ErrQuarantined }
func (m Manager) Headroom(uint64) error                         { return ErrPressure }
