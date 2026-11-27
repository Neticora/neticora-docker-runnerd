package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRuntimeObservationBindsOriginalEnrolledScope(t *testing.T) {
	now := time.Date(2026, 11, 12, 18, 0, 0, 0, time.UTC)
	original := runtimeObservation{"runnerd-runtime-observation-v1", "enrollment:original", "tenant", "host", "boot", "docker-" + strings.Repeat("a", 64), now.Add(-time.Second).Format(time.RFC3339Nano)}
	raw, _ := json.Marshal(original)
	if peer, err := decodeRuntimeObservation(raw, "enrollment:original", "tenant", "host", "boot", now); err != nil || peer != original.EndpointIdentity {
		t.Fatal(peer, err)
	}
	for name, change := range map[string]func(*runtimeObservation){"installation": func(v *runtimeObservation) { v.InstallationID = "replacement" }, "tenant": func(v *runtimeObservation) { v.TenantID = "other" }, "host": func(v *runtimeObservation) { v.HostID = "other" }, "boot": func(v *runtimeObservation) { v.BootID = "other" }, "stale": func(v *runtimeObservation) { v.ObservedAt = now.Add(-6 * time.Minute).Format(time.RFC3339Nano) }, "future": func(v *runtimeObservation) { v.ObservedAt = now.Add(time.Second).Format(time.RFC3339Nano) }, "peer": func(v *runtimeObservation) { v.EndpointIdentity = "docker-" + strings.Repeat("z", 64) }} {
		t.Run(name, func(t *testing.T) {
			v := original
			change(&v)
			raw, _ := json.Marshal(v)
			if _, err := decodeRuntimeObservation(raw, "enrollment:original", "tenant", "host", "boot", now); err == nil {
				t.Fatal("unsafe observation accepted")
			}
		})
	}
}
