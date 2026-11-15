package service

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

const inventoryFreshness = 60 * time.Second

var hostnameFormat = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// These interfaces deliberately expose no execution, ACK, adoption, disposal,
// reservation, or journal-reconciliation operation.
type observationRuntime interface {
	Probe(context.Context) (string, error)
	Inventory(context.Context) ([]string, error)
}
type observationRemote interface {
	Recovery(context.Context, string, protocol.Outbound) (protocol.RecoveryState, error)
	Inventory(context.Context, string, protocol.Outbound) error
}
type inventoryReport struct {
	State, Generation, ObservedAt string
}
type pendingObservation struct {
	message                protocol.Outbound
	generation, observedAt string
}
type inventoryObserver struct {
	mu         sync.Mutex
	runtime    observationRuntime
	remote     observationRemote
	identity   protocol.HostIdentity
	endpoint   string
	localEmpty func(context.Context) (bool, error)
	hostname   func() (string, error)
	now        func() time.Time
	pending    *pendingObservation
	accepted   inventoryReport
}

func (o *inventoryObserver) observe(ctx context.Context, access string) (inventoryReport, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	report := o.accepted
	if report.Generation == "" {
		report.Generation = "0"
	}
	fail := func(state string) (inventoryReport, error) {
		report.State = state
		return report, errors.New("read-only inventory: " + state)
	}
	request, err := protocol.EncodeValidated("RecoveryRequest", map[string]any{"entries": []any{}})
	if err != nil {
		return fail("validation-failed")
	}
	state, err := o.remote.Recovery(ctx, access, request)
	if err != nil {
		return fail("receipt-unavailable")
	}
	if state.Identity != o.identity || state.EndpointIdentity != o.endpoint {
		return fail("binding-mismatch")
	}
	// Heartbeats report the server's accepted generation, including zero before
	// its first receipt. They never advertise a proposed/unconfirmed generation.
	report.Generation = state.InventoryGeneration
	o.accepted.Generation = state.InventoryGeneration
	n, err := strconv.ParseUint(state.InventoryGeneration, 10, 64)
	if err != nil || n == ^uint64(0) {
		return fail("generation-invalid")
	}
	if len(state.Entries) != 0 {
		return fail("unreconciled-platform-resources")
	}
	empty, err := o.localEmpty(ctx)
	if err != nil || !empty {
		return fail("unreconciled-local-resources")
	}
	endpoint, err := o.runtime.Probe(ctx)
	if err != nil || endpoint != o.endpoint {
		return fail("runtime-continuity-required")
	}
	ids, err := o.runtime.Inventory(ctx)
	if err != nil {
		return fail("incomplete-runtime-inventory")
	}
	// Connection-only mode cannot validate execution plans or establish ownership
	// for existing resources. Any candidate therefore requires separate recovery.
	if len(ids) != 0 {
		return fail("unreconciled-runtime-resources")
	}
	endpoint, err = o.runtime.Probe(ctx)
	if err != nil || endpoint != o.endpoint {
		return fail("runtime-continuity-required")
	}
	if o.pending == nil {
		observed := o.now().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
		var hostname any
		if name, e := o.hostname(); e == nil && len(name) <= 253 && hostnameFormat.MatchString(name) {
			hostname = name
		}
		generation := strconv.FormatUint(n+1, 10)
		message, e := protocol.EncodeValidated("InventorySnapshot", map[string]any{"inventoryGeneration": generation, "endpointIdentity": o.endpoint, "complete": true, "observedAt": observed, "resources": []any{}, "hostname": hostname})
		if e != nil {
			return fail("validation-failed")
		}
		o.pending = &pendingObservation{message: message, generation: generation, observedAt: observed}
	}
	if err = o.remote.Inventory(ctx, access, o.pending.message); err != nil {
		if errors.Is(err, transport.ErrInventoryConflict) {
			// Only an observation is discarded. The next pass re-reads the current
			// server generation and re-observes reality; no physical effect exists.
			o.pending = nil
			return fail("publication-conflict")
		}
		return fail("response-uncertain") // Preserve the exact bytes for replay.
	}
	state, err = o.remote.Recovery(ctx, access, request)
	if err != nil {
		return fail("receipt-unavailable")
	}
	if state.Identity != o.identity || state.EndpointIdentity != o.endpoint || len(state.Entries) != 0 {
		return fail("binding-mismatch")
	}
	if state.InventoryGeneration != o.pending.generation {
		o.pending = nil
		return fail("publication-conflict")
	}
	o.accepted = inventoryReport{State: "accepted", Generation: o.pending.generation, ObservedAt: o.pending.observedAt}
	o.pending = nil
	return o.accepted, nil
}
