// Package storetest defines backend-independent recovery-store conformance.
// Adapters run the same tests without exposing a database or SQL to consumers.
package storetest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

var Scope = agent.StoreScope{InstallationID: "install-a", TenantID: "tenant-a", HostID: "host-a", SessionEpoch: "1", EndpointIdentity: "engine-a"}

func Encode(t testing.TB, schema string, v map[string]any) json.RawMessage {
	t.Helper()
	if schema == "HostCommand" && v["kind"] == "start" {
		spec := v["spec"].(map[string]any)
		spec["specHash"] = strings.Repeat("a", 64)
		raw, _ := json.Marshal(spec)
		h, err := protocol.PayloadHashJSON("ExecutionSpec", raw)
		if err != nil {
			t.Fatal(err)
		}
		spec["specHash"] = h
	}
	if schema == "HostCommand" || schema == "HostEvent" {
		v["payloadHash"] = strings.Repeat("a", 64)
		raw, _ := json.Marshal(v)
		h, err := protocol.PayloadHashJSON(schema, raw)
		if err != nil {
			t.Fatal(err)
		}
		v["payloadHash"] = h
	}
	out, err := protocol.EncodeValidated(schema, v)
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func Start(t testing.TB, suffix string) json.RawMessage {
	t.Helper()
	platform := map[string]any{"os": "linux", "architecture": "amd64", "build": "candidate"}
	return Encode(t, "HostCommand", map[string]any{"commandId": "cmd-" + suffix, "kind": "start", "generation": "1", "spec": map[string]any{
		"executionId": "exec-" + suffix, "attemptId": "attempt-" + suffix, "generation": "1", "executionBackend": "customer-host", "runtimeEngine": "docker", "isolationProfile": "standard", "profileVersion": "standard-linux-v1", "templateVersion": "github-linux-v1", "provider": "github", "hostPlatform": platform, "runnerPlatform": platform, "imageDigest": "sha256:" + strings.Repeat("a", 64), "trustClass": "trusted", "dockerBuild": false, "resources": map[string]any{"cpuMillis": "1000", "memoryBytes": "1073741824", "storageBytes": "10737418240", "slots": "1"}, "policyGeneration": "1", "compatibilityRecordId": "candidate-a", "authorizationExpiresAt": time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000Z"), "poolId": "pool-a",
	}})
}

func Object(t testing.TB, raw json.RawMessage) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func Intent(t testing.TB, start json.RawMessage) json.RawMessage {
	t.Helper()
	c := Object(t, start)
	spec := c["spec"].(map[string]any)
	return Encode(t, "StartRequest", map[string]any{"commandId": c["commandId"], "executionId": spec["executionId"], "attemptId": spec["attemptId"], "generation": spec["generation"], "specHash": spec["specHash"], "policyGeneration": spec["policyGeneration"], "startRequestId": "request-" + spec["executionId"].(string), "bootstrapPublicKey": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))})
}
func Event(t testing.TB, start json.RawMessage, sequence uint64, state string) json.RawMessage {
	t.Helper()
	spec := Object(t, start)["spec"].(map[string]any)
	return Encode(t, "HostEvent", map[string]any{"eventId": fmt.Sprintf("event-%s-%d", spec["executionId"], sequence), "executionId": spec["executionId"], "attemptId": spec["attemptId"], "generation": spec["generation"], "sequence": strconv.FormatUint(sequence, 10), "observation": map[string]any{"runtimeRef": map[string]any{"engine": "docker", "scope": "engine-a", "resourceKind": "container", "resourceId": "immutable-" + spec["executionId"].(string), "executionId": spec["executionId"], "generation": spec["generation"], "specHash": spec["specHash"]}, "state": state, "observedAt": time.Now().UTC().Format("2006-01-02T15:04:05.000Z")}})
}
func Proof(t testing.TB, event json.RawMessage, inventory string) agent.AbsenceEvidence {
	t.Helper()
	observation := Object(t, event)["observation"].(map[string]any)
	raw, _ := json.Marshal(observation["runtimeRef"])
	raw, _ = protocol.CanonicalizeJSON(raw)
	at, err := time.Parse(time.RFC3339Nano, observation["observedAt"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return agent.AbsenceEvidence{RuntimeRef: raw, EndpointIdentity: "engine-a", InventoryGeneration: inventory, ObservedAt: at}
}

func Reconcile(t testing.TB, s agent.RecoveryStore, scope agent.StoreScope, inventory string, watermarks ...agent.Watermark) {
	t.Helper()
	h := s.Health(context.Background())
	if err := s.Reconcile(context.Background(), agent.RecoveryCheckpoint{JournalID: h.JournalID, Revision: h.Revision, Scope: scope, InventoryGeneration: inventory, ObservedAt: time.Now(), ServerWatermarks: watermarks}); err != nil {
		t.Fatal(err)
	}
}

func Run(t *testing.T, factory func(*testing.T) agent.RecoveryStore) {
	t.Run("receipt-replay-conflict-and-intent", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		start := Start(t, "a")
		if _, err := s.AcceptCommand(ctx, Scope, start); !errors.Is(err, agent.ErrRecoveryRequired) {
			t.Fatalf("unreconciled acceptance: %v", err)
		}
		Reconcile(t, s, Scope, "1")
		before := s.Health(ctx)
		if _, err := s.Receipt(ctx, Scope, start); !errors.Is(err, agent.ErrNotFound) {
			t.Fatal("receipt lookup admitted missing work", err)
		}
		if after := s.Health(ctx); after.Revision != before.Revision {
			t.Fatal("read-only receipt lookup changed revision")
		}
		r, err := s.AcceptCommand(ctx, Scope, start)
		if err != nil || r.CommandID != "cmd-a" || r.Duplicate {
			t.Fatalf("receipt: %+v %v", r, err)
		}
		r, err = s.AcceptCommand(ctx, Scope, start)
		if err != nil || !r.Duplicate {
			t.Fatalf("replay: %+v %v", r, err)
		}
		if receipt, err := s.Receipt(ctx, Scope, start); err != nil || !receipt.Duplicate {
			t.Fatal("durable receipt unavailable", err)
		}
		changed := Object(t, start)
		changed["spec"].(map[string]any)["poolId"] = "other-pool"
		if _, err = s.AcceptCommand(ctx, Scope, Encode(t, "HostCommand", changed)); !errors.Is(err, agent.ErrConflict) {
			t.Fatalf("conflict accepted: %v", err)
		}
		intent := Intent(t, start)
		for n := 0; n < 2; n++ {
			if err = s.PutStartIntent(ctx, Scope, intent); err != nil {
				t.Fatal(err)
			}
		}
		bad := Object(t, intent)
		bad["startRequestId"] = "replacement-request"
		if err = s.PutStartIntent(ctx, Scope, Encode(t, "StartRequest", bad)); !errors.Is(err, agent.ErrConflict) {
			t.Fatalf("intent replaced: %v", err)
		}
		rows, err := s.Incomplete(ctx, agent.ExecutionCursor{}, 10)
		if err != nil || len(rows) != 1 || !bytes.Equal(rows[0].Command, start) || !bytes.Equal(rows[0].StartRequest, intent) {
			t.Fatalf("immutable snapshot lost: %+v %v", rows, err)
		}
	})
	t.Run("outbox-replay-gaps-conflicts-and-ack-compaction", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		Reconcile(t, s, Scope, "1")
		start := Start(t, "a")
		if _, err := s.AcceptCommand(ctx, Scope, start); err != nil {
			t.Fatal(err)
		}
		first := Event(t, start, 1, "running")
		if err := s.RecordObservation(ctx, Scope, Event(t, start, 2, "running")); !errors.Is(err, agent.ErrConflict) {
			t.Fatalf("gap accepted: %v", err)
		}
		if err := s.RecordObservation(ctx, Scope, first); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordObservation(ctx, Scope, first); err != nil {
			t.Fatal(err)
		}
		conflict := Object(t, first)
		conflict["observation"].(map[string]any)["state"] = "exited"
		if err := s.RecordObservation(ctx, Scope, Encode(t, "HostEvent", conflict)); !errors.Is(err, agent.ErrConflict) {
			t.Fatalf("conflicting event: %v", err)
		}
		if err := s.AckEvents(ctx, Scope, agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "2"}); !errors.Is(err, agent.ErrConflict) {
			t.Fatalf("ack beyond tail: %v", err)
		}
		page := agent.EventPage{ExecutionID: "exec-a", Generation: "1", AfterSequence: "0", Limit: 1}
		for n := 0; n < 2; n++ {
			events, err := s.PendingEvents(ctx, page)
			if err != nil || len(events) != 1 || !bytes.Equal(events[0], first) {
				t.Fatalf("lost-ACK replay changed event: %v", err)
			}
		}
		w := agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "1"}
		for n := 0; n < 2; n++ {
			if err := s.AckEvents(ctx, Scope, w); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.RecordObservation(ctx, Scope, first); err != nil {
			t.Fatal("compaction lost identity", err)
		}
		if err := s.RecordObservation(ctx, Scope, Encode(t, "HostEvent", conflict)); !errors.Is(err, agent.ErrConflict) {
			t.Fatal("compaction lost conflicting hash")
		}
		events, err := s.PendingEvents(ctx, page)
		if err != nil || len(events) != 0 {
			t.Fatal("ACKed payload still pending", err)
		}
		if err = s.RecordObservation(ctx, Scope, Event(t, start, 2, "exited")); err != nil {
			t.Fatal(err)
		}
		if err = s.RecordObservation(ctx, Scope, Event(t, start, 3, "unknown")); err != nil {
			t.Fatal(err)
		}
		if err = s.RecordObservation(ctx, Scope, Event(t, start, 4, "running")); !errors.Is(err, agent.ErrConflict) {
			t.Fatal("terminal fact regressed", err)
		}
	})
	t.Run("cleanup-requires-current-endpoint-absence", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		Reconcile(t, s, Scope, "1")
		start := Start(t, "a")
		if _, err := s.AcceptCommand(ctx, Scope, start); err != nil {
			t.Fatal(err)
		}
		if err := s.RequireCleanup(ctx, Scope, Event(t, start, 1, "cleanup-pending")); err != nil {
			t.Fatal(err)
		}
		cleaned := Event(t, start, 2, "cleaned")
		if err := s.RecordObservation(ctx, Scope, cleaned); !errors.Is(err, agent.ErrConflict) {
			t.Fatal("cleaned bypassed verification")
		}
		if err := s.CompleteCleanup(ctx, Scope, cleaned, agent.AbsenceEvidence{}); !errors.Is(err, agent.ErrRecoveryRequired) {
			t.Fatal("missing evidence accepted", err)
		}
		if err := s.InvalidateRuntime(ctx); err != nil {
			t.Fatal(err)
		}
		if err := s.CompleteCleanup(ctx, Scope, cleaned, Proof(t, cleaned, "1")); !errors.Is(err, agent.ErrRecoveryRequired) {
			t.Fatal("disconnected runtime freed cleanup", err)
		}
		rows, err := s.Incomplete(ctx, agent.ExecutionCursor{}, 10)
		if err != nil || len(rows) != 1 || !rows[0].CleanupPending || rows[0].LastSequence != "1" {
			t.Fatal("cleanup ownership lost", err)
		}
		Reconcile(t, s, Scope, "2", agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "0"})
		bad := Proof(t, cleaned, "2")
		bad.EndpointIdentity = "other-endpoint"
		if err := s.CompleteCleanup(ctx, Scope, cleaned, bad); !errors.Is(err, agent.ErrRecoveryRequired) {
			t.Fatal("wrong endpoint accepted", err)
		}
		if err := s.CompleteCleanup(ctx, Scope, cleaned, Proof(t, cleaned, "2")); err != nil {
			t.Fatal(err)
		}
		rows, err = s.Incomplete(ctx, agent.ExecutionCursor{}, 10)
		if err != nil || len(rows) != 1 || rows[0].State != "cleaned" || rows[0].CleanupPending {
			t.Fatal("cleaned event lost before ACK", err)
		}
		if err = s.AckEvents(ctx, Scope, agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "2"}); err != nil {
			t.Fatal(err)
		}
		rows, err = s.Incomplete(ctx, agent.ExecutionCursor{}, 10)
		if err != nil || len(rows) != 0 {
			t.Fatal("completed work stayed incomplete", err)
		}
	})
	t.Run("concurrent-delivery-and-bounded-pages", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		Reconcile(t, s, Scope, "1")
		start := Start(t, "a")
		var wg sync.WaitGroup
		errs := make(chan error, 12)
		for n := 0; n < 12; n++ {
			wg.Add(1)
			go func() { defer wg.Done(); _, err := s.AcceptCommand(ctx, Scope, start); errs <- err }()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.AcceptCommand(ctx, Scope, Start(t, "b")); err != nil {
			t.Fatal(err)
		}
		rows, err := s.Incomplete(ctx, agent.ExecutionCursor{}, 1)
		if err != nil || len(rows) != 1 {
			t.Fatal(err)
		}
		next, err := s.Incomplete(ctx, agent.ExecutionCursor{ExecutionID: rows[0].Identity.ExecutionID, Generation: rows[0].Identity.Generation}, 1)
		if err != nil || len(next) != 1 || next[0].Identity.ExecutionID == rows[0].Identity.ExecutionID {
			t.Fatal("cursor failed", err)
		}
		if _, err = s.Incomplete(ctx, agent.ExecutionCursor{}, 101); err == nil {
			t.Fatal("unbounded query allowed")
		}
		wrong := Scope
		wrong.TenantID = "other"
		if _, err = s.AcceptCommand(ctx, wrong, Start(t, "c")); !errors.Is(err, agent.ErrConflict) {
			t.Fatal("wrong tenant accepted", err)
		}
	})
	t.Run("runtime-loss-retains-recovery-reporting", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		Reconcile(t, s, Scope, "1")
		start := Start(t, "a")
		if _, err := s.AcceptCommand(ctx, Scope, start); err != nil {
			t.Fatal(err)
		}
		first := Event(t, start, 1, "running")
		if err := s.RecordObservation(ctx, Scope, first); err != nil {
			t.Fatal(err)
		}
		if err := s.InvalidateRuntime(ctx); err != nil {
			t.Fatal(err)
		}
		if s.Health(ctx).Ready {
			t.Fatal("unknown runtime remained ready")
		}
		if _, err := s.AcceptCommand(ctx, Scope, Start(t, "b")); !errors.Is(err, agent.ErrRecoveryRequired) {
			t.Fatal("unknown runtime admitted new start", err)
		}
		events, err := s.PendingEvents(ctx, agent.EventPage{ExecutionID: "exec-a", Generation: "1", AfterSequence: "0", Limit: 10})
		if err != nil || len(events) != 1 || !bytes.Equal(events[0], first) {
			t.Fatal("runtime outage blocked committed outcome delivery", err)
		}
		if err = s.RecordObservation(ctx, Scope, Event(t, start, 2, "unknown")); err != nil {
			t.Fatal("runtime uncertainty lost durable observation", err)
		}
		cancel := Encode(t, "HostCommand", map[string]any{"commandId": "cancel-a", "kind": "cancel", "executionId": "exec-a", "generation": "1"})
		if _, err = s.AcceptCommand(ctx, Scope, cancel); err != nil {
			t.Fatal("runtime outage blocked cancellation receipt", err)
		}
		if err = s.RequireCleanup(ctx, Scope, Event(t, start, 3, "cleanup-pending")); err != nil {
			t.Fatal("runtime outage lost cleanup obligation", err)
		}
		if err = s.AckEvents(ctx, Scope, agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "2"}); err != nil {
			t.Fatal("runtime outage blocked durable ACK", err)
		}
		rows, err := s.Incomplete(ctx, agent.ExecutionCursor{}, 10)
		if err != nil || len(rows) != 1 || !rows[0].CleanupPending {
			t.Fatal("runtime outage released ownership", err)
		}
	})
	t.Run("successor-generation-waits-for-final-event-ack", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		Reconcile(t, s, Scope, "1")
		start := Start(t, "a")
		if _, err := s.AcceptCommand(ctx, Scope, start); err != nil {
			t.Fatal(err)
		}
		if err := s.RequireCleanup(ctx, Scope, Event(t, start, 1, "cleanup-pending")); err != nil {
			t.Fatal(err)
		}
		cleaned := Event(t, start, 2, "cleaned")
		if err := s.CompleteCleanup(ctx, Scope, cleaned, Proof(t, cleaned, "1")); err != nil {
			t.Fatal(err)
		}
		if err := s.AckEvents(ctx, Scope, agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "1"}); err != nil {
			t.Fatal(err)
		}
		next := Object(t, start)
		next["commandId"] = "cmd-a-next"
		next["generation"] = "2"
		spec := next["spec"].(map[string]any)
		spec["generation"] = "2"
		spec["attemptId"] = "attempt-a-next"
		nextRaw := Encode(t, "HostCommand", next)
		if _, err := s.AcceptCommand(ctx, Scope, nextRaw); !errors.Is(err, agent.ErrConflict) {
			t.Fatal("successor accepted before cleanup event ACK", err)
		}
		if err := s.AckEvents(ctx, Scope, agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "2"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.AcceptCommand(ctx, Scope, nextRaw); err != nil {
			t.Fatal("acknowledged cleanup did not unblock successor", err)
		}
	})
}
