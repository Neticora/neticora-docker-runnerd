//go:build linux

package katalinux

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

// Request-local, observation-only instrumentation. No environment switch or
// cached safety result is introduced. Callers may attach this to a diagnostic
// context; ordinary cleanup has no collector and unchanged checks.
type sandboxMetricsKey struct{}

type sandboxTiming struct {
	Calls int64 `json:"calls"`
	Nanos int64 `json:"nanos"`
}

type sandboxMetrics struct {
	mu         sync.Mutex
	Operations map[string]sandboxTiming `json:"operations"`
	Entries    int                      `json:"entries"`
	MaxDepth   int                      `json:"maxDepth"`
	counters   [12]atomic.Int64
}

var sandboxCounterNames = [12]string{"fdStat", "mountPointStat", "mapsRead", "mapsDecodeHit", "mapsDecode", "mountinfoRead", "mountDecodeHit", "mountDecode", "namespaceTask", "namespaceProcEnumeration", "blockTask", "blockProcEnumeration"}

func sandboxCount(ctx context.Context, operation string) {
	if m, _ := ctx.Value(sandboxMetricsKey{}).(*sandboxMetrics); m != nil {
		for i, name := range sandboxCounterNames {
			if operation == name {
				m.counters[i].Add(1)
				return
			}
		}
		m.record(operation, 0)
	}
}

// Hot syscall counters avoid a diagnostic map mutex per FD/mountpoint. They
// still count every operation; this changes no observation or safety decision.
func (m *sandboxMetrics) MarshalJSON() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ops := make(map[string]sandboxTiming, len(m.Operations)+len(sandboxCounterNames))
	for name, value := range m.Operations {
		ops[name] = value
	}
	for i, name := range sandboxCounterNames {
		if n := m.counters[i].Load(); n != 0 {
			value := ops[name]
			value.Calls += n
			ops[name] = value
		}
	}
	return json.Marshal(struct {
		Operations map[string]sandboxTiming `json:"operations"`
		Entries    int                      `json:"entries"`
		MaxDepth   int                      `json:"maxDepth"`
	}{ops, m.Entries, m.MaxDepth})
}

func sandboxTimed(ctx context.Context, operation string, call func() error) error {
	m, _ := ctx.Value(sandboxMetricsKey{}).(*sandboxMetrics)
	if m == nil {
		return call()
	}
	start := time.Now()
	err := call()
	m.record(operation, time.Since(start))
	return err
}

func (m *sandboxMetrics) record(operation string, elapsed time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Operations == nil {
		m.Operations = map[string]sandboxTiming{}
	}
	v := m.Operations[operation]
	v.Calls++
	v.Nanos += elapsed.Nanoseconds()
	m.Operations[operation] = v
}

func sandboxMetadata(ctx context.Context) func() {
	m, _ := ctx.Value(sandboxMetricsKey{}).(*sandboxMetrics)
	if m == nil {
		return func() {}
	}
	start := time.Now()
	return func() { m.record("metadata", time.Since(start)) }
}

func sandboxVisit(ctx context.Context, depth int) {
	m, _ := ctx.Value(sandboxMetricsKey{}).(*sandboxMetrics)
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Entries++
	if depth > m.MaxDepth {
		m.MaxDepth = depth
	}
}
