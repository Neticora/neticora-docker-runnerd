package broker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

// Receipt is a durable intent, not physical-absence or execution authorization.
// This initial append-only format deliberately cannot mark cleanup successful.
type Receipt struct {
	Version     string  `json:"version"`
	OperationID string  `json:"operationId"`
	Operation   string  `json:"operation"`
	PayloadHash string  `json:"payloadHash"`
	Binding     Binding `json:"binding"`
	State       string  `json:"state"`
}

type Ledger struct {
	mu     sync.Mutex
	root   *os.Root
	lock   *os.File
	failed bool
}

func OpenLedger(path string) (*Ledger, error) {
	r, err := hostfs.OpenState(path)
	if err != nil {
		return nil, err
	}
	if err = durableStorage(r); err != nil {
		r.Close()
		return nil, err
	}
	lock, err := hostfs.Lock(r)
	if err != nil {
		r.Close()
		return nil, err
	}
	info, err := lock.Stat()
	if err != nil || !ownedRecord(info) {
		lock.Close()
		r.Close()
		return nil, ErrRejected
	}
	return &Ledger{root: r, lock: lock}, nil
}

func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Close the directory before releasing exclusive lifecycle ownership.
	err := l.root.Close()
	if e := l.lock.Close(); err == nil {
		err = e
	}
	l.failed = true
	return err
}

func (l *Ledger) read(id string) (Receipt, error) {
	var receipt Receipt
	if !digest(id) || l.failed {
		return receipt, ErrRejected
	}
	info, err := l.root.Lstat(id + ".json")
	if err != nil {
		return receipt, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > MaxMessage || !ownedRecord(info) {
		return receipt, ErrRejected
	}
	// The protected directory is writable only by this process/host admin.
	raw, err := l.root.ReadFile(id + ".json")
	if err != nil || decode(raw, &receipt) != nil || receipt.Version != Version || receipt.OperationID != id || receipt.State != "RECOVERY_REQUIRED" || !receipt.Binding.valid() || !digest(receipt.PayloadHash) || !intentOperation(receipt.Operation) {
		return Receipt{}, ErrRejected
	}
	return receipt, nil
}

func intentOperation(op string) bool {
	switch op {
	case "PrepareImage", "AllocateExecutionResources", "CreateExecution", "StartExecution", "StopExecution", "RemoveExecution", "DisposeUnstarted", "CleanupExecutionResources":
		return true
	}
	return false
}

func (l *Ledger) Get(id string) (Receipt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.read(id)
}

// Begin persists immutable intent before a future backend may have effects.
// Duplicate returns true: caller must reconcile, never blindly repeat an effect.
// There is no runtime backend in the foundation, and this is not exposed as RPC.
func (l *Ledger) Begin(id, operation string, binding Binding, payload []byte) (Receipt, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.begin(id, operation, binding, payload)
}

func (l *Ledger) begin(id, operation string, binding Binding, payload []byte) (Receipt, bool, error) {
	if !digest(id) || !intentOperation(operation) || !binding.valid() || l.failed || len(payload) > MaxMessage {
		return Receipt{}, false, ErrRejected
	}
	hash := sha256.Sum256(payload)
	want := Receipt{Version: Version, OperationID: id, Operation: operation, PayloadHash: hex.EncodeToString(hash[:]), Binding: binding, State: "RECOVERY_REQUIRED"}
	old, err := l.read(id)
	if err == nil {
		if old != want {
			return Receipt{}, false, ErrConflict
		}
		return old, true, nil
	}
	if !os.IsNotExist(err) {
		return Receipt{}, false, err
	}
	raw, err := json.Marshal(want)
	if err != nil {
		return Receipt{}, false, err
	}
	f, err := l.root.OpenFile(id+".json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return Receipt{}, false, err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err == nil {
		dir, e := l.root.Open(".")
		if e == nil {
			e = dir.Sync()
			if closeErr := dir.Close(); e == nil {
				e = closeErr
			}
		}
		err = e
	}
	if err != nil {
		l.failed = true
		return Receipt{}, false, err
	}
	return want, false, nil
}
