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
	AttemptID      string
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
