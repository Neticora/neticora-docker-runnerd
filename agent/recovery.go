package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrConflict         = errors.New("recovery identity or payload conflict")
	ErrNotFound         = errors.New("recovery record not found")
	ErrRecoveryRequired = errors.New("authoritative recovery reconciliation required")
	ErrStoreUnavailable = errors.New("recovery store unavailable; retain evidence")
	ErrCapacity         = errors.New("recovery storage headroom exhausted")
	ErrMaintenance      = errors.New("recovery maintenance in progress; retry launch later")
)

// StoreScope comes from authenticated host context, never a command's claims.
type StoreScope struct {
	InstallationID   string
	TenantID         string
	HostID           string
	SessionEpoch     string
	EndpointIdentity string
}

type Receipt struct {
	CommandID   string
	PayloadHash string
	Generation  string
	Duplicate   bool
}

type Execution struct {
	Identity       Identity
	CommandID      string
	Command        json.RawMessage
	StartRequest   json.RawMessage
	State          string
	RuntimeRef     json.RawMessage
	CleanupPending bool
	LastSequence   string
	AckSequence    string
}

// Pages use an exclusive execution-ID/generation cursor or an event sequence.
// No query loads an unbounded journal into memory.
type ExecutionCursor struct{ ExecutionID, Generation string }

// ReservationLimits are host-local ceilings after policy narrowing and runtime
// overhead/headroom have been accounted for. Zero means no launch capacity.
type ReservationLimits struct{ CPUMillis, MemoryBytes, StorageBytes, Slots uint64 }
type EventPage struct {
	ExecutionID, Generation, AfterSequence string
	Limit                                  int
}
type StoreHealth struct {
	JournalID string
	Revision  string
	Ready     bool
	Reason    string
}

// RecoveryCheckpoint is assembled by a trusted controller AFTER authenticated
// SaaS reconciliation and fresh complete runtime inventory. JournalID/Revision
// bind the exact local snapshot reviewed by that controller. ServerWatermarks
// must cover every unresolved local execution and never trail a locally committed
// ACK. Cleaned executions whose final facts are durably ACKed are retired from
// reconciliation, not deleted: their receipts, ACKs and creation fences remain.
// Supplying this value is not itself proof of authentication or authorization.
type RecoveryCheckpoint struct {
	JournalID           string
	Revision            string
	Scope               StoreScope
	InventoryGeneration string
	ObservedAt          time.Time
	ServerWatermarks    []Watermark
}
type Watermark struct{ ExecutionID, Generation, ContiguousSequence string }

// AbsenceEvidence is produced only by trusted current-endpoint inspection plus
// complete scoped inventory, outside the database transaction. Removal replies,
// provider completion and untrusted wire booleans cannot produce this value.
type AbsenceEvidence struct {
	RuntimeRef          json.RawMessage
	EndpointIdentity    string
	InventoryGeneration string
	ObservedAt          time.Time
}

// RecoveryStore persists receipt before ACK, start identity before issuance,
// and state/required events/cleanup together. Payloads are strictly validated
// HostCommand, StartRequest and HostEvent snapshots, not arbitrary state blobs.
// Runtime, provider and transport calls always occur outside these operations.
// SQLite is one adapter; the protocol and runtime never receive SQL handles.
type RecoveryStore interface {
	AcceptCommand(context.Context, StoreScope, json.RawMessage) (Receipt, error)
	Receipt(context.Context, StoreScope, json.RawMessage) (Receipt, error)
	PutStartIntent(context.Context, StoreScope, json.RawMessage) error
	RecordObservation(context.Context, StoreScope, json.RawMessage) error
	RequireCleanup(context.Context, StoreScope, json.RawMessage) error
	CompleteCleanup(context.Context, StoreScope, json.RawMessage, AbsenceEvidence) error
	AckEvents(context.Context, StoreScope, Watermark) error
	PendingEvents(context.Context, EventPage) ([]json.RawMessage, error)
	Incomplete(context.Context, ExecutionCursor, int) ([]Execution, error)
	// Executions includes acknowledged cleaned history needed for full watermark
	// reconciliation; identical bounded cursor semantics to Incomplete.
	Executions(context.Context, ExecutionCursor, int) ([]Execution, error)
	Reconcile(context.Context, RecoveryCheckpoint) error
	InvalidateRuntime(context.Context) error
	Health(context.Context) StoreHealth
}
