package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

type observedRuntime struct {
	endpoint string
	ids      []string
	err      error
	probes   int
	replace  bool
}

func (r *observedRuntime) Probe(context.Context) (string, error) {
	r.probes++
	if r.replace && r.probes > 1 {
		return "replacement", nil
	}
	return r.endpoint, nil
}
func (r *observedRuntime) Inventory(context.Context) ([]string, error) { return r.ids, r.err }

type observationGateway struct {
	identity                                 protocol.HostIdentity
	generation                               uint64
	endpoint                                 string
	entries                                  []protocol.RecoveryEntry
	payload                                  []byte
	posts                                    [][]byte
	loseBefore, loseAfter, conflict, offline bool
}

func (g *observationGateway) Recovery(context.Context, string, protocol.Outbound) (protocol.RecoveryState, error) {
	if g.offline {
		return protocol.RecoveryState{}, errors.New("offline")
	}
	return protocol.RecoveryState{Identity: g.identity, EndpointIdentity: g.endpoint, InventoryGeneration: strconv.FormatUint(g.generation, 10), Entries: g.entries}, nil
}
func (g *observationGateway) Inventory(_ context.Context, _ string, message protocol.Outbound) error {
	raw := message.Bytes()
	g.posts = append(g.posts, append([]byte{}, raw...))
	if g.loseBefore {
		g.loseBefore = false
		return errors.New("lost response before commit")
	}
	var snapshot protocol.InventorySnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return err
	}
	n, _ := strconv.ParseUint(string(snapshot.InventoryGeneration), 10, 64)
	if g.conflict {
		g.conflict = false
		g.generation++
		return transport.ErrInventoryConflict
	}
	if n == g.generation && bytes.Equal(raw, g.payload) {
		return nil
	}
	if n != g.generation+1 {
		return transport.ErrInventoryConflict
	}
	g.generation = n
	g.payload = append([]byte{}, raw...)
	if g.loseAfter {
		g.loseAfter = false
		return errors.New("lost response after commit")
	}
	return nil
}
func observationFixture() (*inventoryObserver, *observedRuntime, *observationGateway) {
	identity := protocol.HostIdentity{HostId: "host-a", KeyId: "key-a", KeyVersion: "1", SessionEpoch: "1"}
	runtime := &observedRuntime{endpoint: "engine-a"}
	gateway := &observationGateway{identity: identity, endpoint: "engine-a"}
	observer := &inventoryObserver{runtime: runtime, remote: gateway, identity: identity, endpoint: "engine-a", localEmpty: func(context.Context) (bool, error) { return true, nil }, hostname: func() (string, error) { return "runnerd-clean", nil }, now: time.Now}
	return observer, runtime, gateway
}
func TestObserverConsecutiveAndRestart(t *testing.T) {
	o, _, g := observationFixture()
	for i := 1; i <= 3; i++ {
		report, err := o.observe(context.Background(), "auth")
		if err != nil || report.Generation != strconv.Itoa(i) {
			t.Fatal(report, err)
		}
	}
	restarted, _, _ := observationFixture()
	restarted.remote = g
	report, err := restarted.observe(context.Background(), "auth")
	if err != nil || report.Generation != "4" {
		t.Fatal(report, err)
	}
	var payload map[string]any
	_ = json.Unmarshal(g.payload, &payload)
	if payload["hostname"] != "runnerd-clean" || len(payload["resources"].([]any)) != 0 {
		t.Fatal(payload)
	}
}
func TestObserverAmbiguousResponsesReplayExactBytes(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			o, _, g := observationFixture()
			g.loseAfter = after
			g.loseBefore = !after
			if _, err := o.observe(context.Background(), "auth"); err == nil {
				t.Fatal("expected uncertainty")
			}
			original := append([]byte{}, g.posts[0]...)
			o.hostname = func() (string, error) { return "renamed-host", nil }
			o.now = func() time.Time { return time.Now().Add(time.Minute) }
			report, err := o.observe(context.Background(), "new-auth")
			if err != nil || report.Generation != "1" {
				t.Fatal(report, err)
			}
			if !bytes.Equal(original, g.posts[1]) {
				t.Fatal("ambiguous snapshot replaced")
			}
			if _, err = o.observe(context.Background(), "auth"); err != nil {
				t.Fatal(err)
			}
			var payload map[string]any
			_ = json.Unmarshal(g.payload, &payload)
			if payload["hostname"] != "renamed-host" {
				t.Fatal(payload)
			}
		})
	}
}
func TestObserverOwnershipAndContinuityBlockPublication(t *testing.T) {
	cases := []string{"local", "local-error", "platform", "unknown-runtime", "incomplete-runtime", "endpoint", "socket-replaced", "session", "key"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			o, r, g := observationFixture()
			switch name {
			case "local":
				o.localEmpty = func(context.Context) (bool, error) { return false, nil }
			case "local-error":
				o.localEmpty = func(context.Context) (bool, error) { return true, errors.New("unreadable") }
			case "platform":
				g.entries = []protocol.RecoveryEntry{{}}
			case "unknown-runtime":
				r.ids = []string{"unknown-container"}
			case "incomplete-runtime":
				r.err = errors.New("partial list")
			case "endpoint":
				r.endpoint = "other"
			case "socket-replaced":
				r.replace = true
			case "session":
				g.identity.SessionEpoch = "2"
			case "key":
				g.identity.KeyId = "replacement"
			}
			if _, err := o.observe(context.Background(), "auth"); err == nil || len(g.posts) != 0 {
				t.Fatal("unsafe publication", g.posts, err)
			}
		})
	}
}
func TestObserverConcurrentAndConflictingPublication(t *testing.T) {
	o, _, g := observationFixture()
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := o.observe(context.Background(), "auth"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if g.generation != 20 {
		t.Fatal(g.generation)
	}
	g.conflict = true
	if _, err := o.observe(context.Background(), "auth"); err == nil {
		t.Fatal("concurrent conflict hidden")
	}
	report, err := o.observe(context.Background(), "auth")
	if err != nil || report.Generation != "22" {
		t.Fatal(report, err)
	}
}
func TestObserverFreshnessSeparateFromConnectivity(t *testing.T) {
	o, _, g := observationFixture()
	o.now = func() time.Time { return time.Now().Add(-2 * time.Minute) }
	report, err := o.observe(context.Background(), "auth")
	if err != nil {
		t.Fatal(err)
	}
	s := &connectionStatus{}
	s.set("connected", time.Now().UTC().Format(time.RFC3339Nano))
	s.setInventory(report)
	if _, fresh := s.inventoryStatus(); fresh {
		t.Fatal("stale observation advertised fresh")
	}
	g.offline = true
	report, err = o.observe(context.Background(), "auth")
	if err == nil {
		t.Fatal("outage hidden")
	}
	s.setInventory(report)
	connection, _ := s.get()
	if connection != "connected" {
		t.Fatal("inventory overwrote heartbeat status")
	}
	if _, fresh := s.inventoryStatus(); fresh {
		t.Fatal("outage refreshed inventory")
	}
}
func TestObserverHostnameUnavailableAndInvalid(t *testing.T) {
	for _, name := range []string{"", "bad\nname", "-invalid", "a..b", string(bytes.Repeat([]byte("x"), 64))} {
		o, _, g := observationFixture()
		o.hostname = func() (string, error) { return name, nil }
		if _, err := o.observe(context.Background(), "auth"); err != nil {
			t.Fatal(err)
		}
		var data map[string]any
		_ = json.Unmarshal(g.payload, &data)
		if data["hostname"] != nil {
			t.Fatal("invalid hostname transmitted", data)
		}
	}
}

func TestInventoryFailureCannotBeHiddenByFreshHeartbeat(t *testing.T) {
	o, _, gateway := observationFixture()
	report, err := o.observe(context.Background(), "auth")
	if err != nil {
		t.Fatal(err)
	}
	status := &connectionStatus{}
	status.set("connected", time.Now().UTC().Format(time.RFC3339Nano))
	status.setInventory(report)
	if _, fresh := status.inventoryStatus(); !fresh {
		t.Fatal("accepted inventory not fresh")
	}
	gateway.offline = true
	report, err = o.observe(context.Background(), "auth")
	if err == nil {
		t.Fatal("inventory failure hidden")
	}
	status.setInventory(report)
	if platform, _ := status.get(); platform != "connected" {
		t.Fatal("inventory failure changed heartbeat connectivity")
	}
	if _, fresh := status.inventoryStatus(); fresh {
		t.Fatal("heartbeat masked failed inventory observation")
	}
}
