//go:build linux

package journal

import (
	"sync"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
)

func TestStickyCacheCASAcrossRestartAndColdFallback(t *testing.T) {
	ctx := t.Context()
	dir := privateDir(t)
	s := recovery(t, dir, Options{})
	storetest.Reconcile(t, s, storetest.Scope, "1")
	const key = "repository-key"
	prepare := func(id string, cold bool) KataCacheVolume {
		t.Helper()
		if _, err := s.AcceptCommand(ctx, storetest.Scope, storetest.Start(t, id)); err != nil {
			t.Fatal(err)
		}
		cursor := agent.ExecutionCursor{ExecutionID: "exec-" + id, Generation: "1"}
		if err := s.BeginKataCache(ctx, storetest.Scope, cursor, key, "lv-"+id, cold); err != nil {
			t.Fatal(err)
		}
		v, found, err := s.KataCacheAttempt(ctx, cursor)
		if err != nil || !found {
			t.Fatalf("read volume: %+v %v %v", v, found, err)
		}
		if !cold {
			if err := s.ReadyKataCache(ctx, v, "uuid-"+id, "filesystem-"+id); err != nil {
				t.Fatal(err)
			}
		}
		return v
	}
	seed := prepare("a", false)
	if err := s.MarkKataCacheCleanExit(ctx, seed); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteKataCache(ctx, seed, true); err != nil {
		t.Fatal(err)
	}
	left, right := prepare("b", false), prepare("c", false)
	cold := prepare("d", true)
	unproven := prepare("e", false)
	for _, v := range []KataCacheVolume{left, right} {
		if v.ParentUUID != "uuid-a" {
			t.Fatalf("unexpected parent: %+v", v)
		}
		if err := s.MarkKataCacheCleanExit(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CompleteKataCache(ctx, unproven, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = recovery(t, dir, Options{})
	storetest.Reconcile(t, s, storetest.Scope, "2",
		agent.Watermark{ExecutionID: "exec-a", Generation: "1", ContiguousSequence: "0"},
		agent.Watermark{ExecutionID: "exec-b", Generation: "1", ContiguousSequence: "0"},
		agent.Watermark{ExecutionID: "exec-c", Generation: "1", ContiguousSequence: "0"},
		agent.Watermark{ExecutionID: "exec-d", Generation: "1", ContiguousSequence: "0"},
		agent.Watermark{ExecutionID: "exec-e", Generation: "1", ContiguousSequence: "0"})
	var contenders sync.WaitGroup
	for _, v := range []KataCacheVolume{left, right} {
		contenders.Go(func() {
			if err := s.CompleteKataCache(ctx, v, true); err != nil {
				t.Error(err)
			}
		})
	}
	contenders.Wait()
	head, found, err := s.KataCacheHead(ctx, key)
	if err != nil || !found || (head.UUID != "uuid-b" && head.UUID != "uuid-c") {
		t.Fatalf("head: %+v %v %v", head, found, err)
	}
	coldCursor := agent.ExecutionCursor{ExecutionID: cold.ExecutionID, Generation: "1"}
	if err := s.BeginKataCache(ctx, storetest.Scope, coldCursor, key, "lv-d", false); err != nil {
		t.Fatal(err)
	}
	actual, exists, err := s.KataCacheAttempt(ctx, coldCursor)
	if err != nil || !exists || actual.State != "cold" {
		t.Fatalf("cold fallback changed after restart: %+v %v %v", actual, exists, err)
	}
	garbage, err := s.KataCacheGarbage(ctx, key, 1)
	if err != nil || len(garbage) != 3 {
		t.Fatalf("garbage: %+v %v", garbage, err)
	}
	for _, v := range garbage {
		if v.Name == head.Name || v.Name == cold.Name {
			t.Fatalf("live storage marked as garbage: %+v", v)
		}
	}
}

func TestTerminalCleanupRetiresOnlyItsDisklessCacheRecord(t *testing.T) {
	ctx := t.Context()
	s := recovery(t, privateDir(t), Options{})
	start := accepted(t, s)
	cold := agent.ExecutionCursor{ExecutionID: "exec-a", Generation: "1"}
	if err := s.BeginKataCache(ctx, storetest.Scope, cold, "repository-key", "lv-cold", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptCommand(ctx, storetest.Scope, storetest.Start(t, "b")); err != nil {
		t.Fatal(err)
	}
	warm := agent.ExecutionCursor{ExecutionID: "exec-b", Generation: "1"}
	if err := s.BeginKataCache(ctx, storetest.Scope, warm, "repository-key", "lv-warm", false); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireCleanup(ctx, storetest.Scope, storetest.Event(t, start, 1, "cleanup-pending")); err != nil {
		t.Fatal(err)
	}
	event := storetest.Event(t, start, 2, "cleaned")
	for range 2 {
		if err := s.CompleteCleanup(ctx, storetest.Scope, event, storetest.Proof(t, event, "1")); err != nil {
			t.Fatal(err)
		}
	}
	if _, exists, err := s.KataCacheAttempt(ctx, cold); err != nil || exists {
		t.Fatalf("diskless cache record survived cleanup: exists=%v err=%v", exists, err)
	}
	if v, exists, err := s.KataCacheAttempt(ctx, warm); err != nil || !exists || v.State != "preparing" {
		t.Fatalf("cleanup changed another execution's cache: %+v exists=%v err=%v", v, exists, err)
	}
}
