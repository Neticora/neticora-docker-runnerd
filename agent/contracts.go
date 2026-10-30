// Package agent defines portable execution and recovery boundaries. Wire values
// do not establish authority. Implementations must commit intent before effects.
package agent

import "context"

type Identity struct {
	InstallationID string
	TenantID       string
	HostID         string
	ExecutionID    string
	Generation     string
	SpecHash       string
}
type RuntimeRef struct {
	Identity             Identity
	Endpoint, ResourceID string
}
type Observation struct {
	Ref   RuntimeRef
	State string
}
type Snapshot struct {
	Observations []Observation
	Complete     bool
}

// Runtime never owns daemon lifetime. Cancellation stops an operation, not an
// already-running workflow; Stop/Remove require separately authorized intent.
// Implementations do not administer customer host firewall, DNS, routes, proxies,
// destination filtering or address pools. Workload attachment uses explicitly
// customer-approved runtime networking; credential/management isolation remains
// mandatory independently of customer network policy.
type Runtime interface {
	Probe(context.Context) (Snapshot, error)
	Ensure(context.Context, Identity) (Observation, error)
	Inspect(context.Context, RuntimeRef) (Observation, error)
	Inventory(context.Context) (Snapshot, error)
	Stop(context.Context, RuntimeRef) error
	Remove(context.Context, RuntimeRef) error
}

// RecoveryStore is independent of SQL and persists receipt before ACK. Commit
// must atomically apply state and required outgoing facts; no network/runtime
// calls belong inside it. Cleanup obligations survive process termination.
type RecoveryStore interface {
	Commit(context.Context, Transition) error
	Pending(context.Context, int) ([]Transition, error)
}
type Transition struct {
	Identity               Identity
	CommandID, PayloadHash string
	State                  []byte
	Events                 [][]byte
	CleanupPending         bool
}
