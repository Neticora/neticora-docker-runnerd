//go:build linux

package katalinux

import (
	"testing"
	"time"
)

func TestStandaloneStartupHeartbeatGrace(t *testing.T) {
	start := time.Unix(1770000000, 0)
	profile := Profile{Manifest: Manifest{Standalone: true, Deadlines: Deadlines{
		StartupSeconds: 90, HeartbeatSeconds: 30, ExecutionSeconds: 600,
	}}}
	initial := start.Add(9 * time.Second)
	if !profile.freshHeartbeat(start, initial, start.Add(40*time.Second)) {
		t.Fatal("initial heartbeat lost the remaining startup window")
	}
	if profile.freshHeartbeat(start, initial, start.Add(91*time.Second)) {
		t.Fatal("stale heartbeat exceeded the startup window")
	}
	if !profile.freshHeartbeat(start, start.Add(89*time.Second), start.Add(91*time.Second)) {
		t.Fatal("fresh heartbeat did not preserve running guest")
	}
	if profile.freshHeartbeat(start, start.Add(-time.Second), start.Add(10*time.Second)) ||
		profile.freshHeartbeat(start, start.Add(16*time.Second), start.Add(10*time.Second)) {
		t.Fatal("startup accepted a heartbeat outside its valid time range")
	}
	profile.Manifest.Standalone = false
	if profile.freshHeartbeat(start, initial, start.Add(40*time.Second)) {
		t.Fatal("standalone startup grace changed other profiles")
	}
}
