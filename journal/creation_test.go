package journal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) ([]byte, []byte, Authority, ed25519.PrivateKey) {
	t.Helper()
	raw, e := os.ReadFile("../api/fixtures/validation.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixtures []struct {
		Schema string          `json:"schema"`
		Value  json.RawMessage `json:"value"`
		Valid  bool            `json:"valid"`
	}
	if e = json.Unmarshal(raw, &fixtures); e != nil {
		t.Fatal(e)
	}
	var start map[string]any
	for _, f := range fixtures {
		if f.Schema == "HostCommand" && f.Valid {
			if e = json.Unmarshal(f.Value, &start); e != nil {
				t.Fatal(e)
			}
			if start["kind"] == "start" {
				break
			}
			start = nil
		}
	}
	if start == nil {
		t.Fatal("missing start fixture")
	}
	spec := start["spec"].(map[string]any)
	spec["authorizationExpiresAt"] = time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
	delete(spec, "specHash")
	spec["specHash"], _ = hash(spec)
	delete(start, "payloadHash")
	start["payloadHash"], _ = hash(start)
	a := Authority{TenantID: "tenant-a", HostID: "host-a", SessionEpoch: "1", EndpointIdentity: "engine-a", KeyID: "key-a"}
	b, e := binding(start, a)
	if e != nil {
		t.Fatal(e)
	}
	f := map[string]any{"kind": "fence-never-started", "commandId": "fence-a", "payloadHash": "", "challenge": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "issuedAt": time.Now().Add(-time.Second).UTC().Format("2006-01-02T15:04:05.000Z")}
	for k, v := range b {
		if k != "attemptId" {
			f[k] = v
		}
	}
	delete(f, "payloadHash")
	f["payloadHash"], _ = hash(f)
	s, _ := canonical(start)
	fraw, _ := canonical(f)
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return s, fraw, a, key
}
func open(t *testing.T, path string) *Store {
	t.Helper()
	if e := os.Chmod(path, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestFenceSurvivesRestartAndSignsExactBoundary(t *testing.T) {
	start, fence, a, key := fixture(t)
	dir := t.TempDir()
	s := open(t, dir)
	raw, e := s.FenceNeverStarted(start, fence, a, key, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	var p map[string]any
	if e = json.Unmarshal(raw, &p); e != nil {
		t.Fatal(e)
	}
	sig, e := base64.RawURLEncoding.DecodeString(p["signature"].(string))
	if e != nil {
		t.Fatal(e)
	}
	delete(p, "signature")
	message, _ := canonical(p)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), message, sig) {
		t.Fatal("invalid proof signature")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s = open(t, dir)
	defer s.Close()
	if e = s.ClaimCreation(start, a); e == nil {
		t.Fatal("fenced creation permitted")
	}
	again, e := s.FenceNeverStarted(start, fence, a, key, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	var q map[string]any
	json.Unmarshal(again, &q)
	if q["journalId"] != p["journalId"] || q["fencedAt"] != p["fencedAt"] {
		t.Fatal("tombstone identity changed")
	}
}
func TestCreationClaimRemainsUncertainAfterCrash(t *testing.T) {
	start, fence, a, key := fixture(t)
	dir := t.TempDir()
	s := open(t, dir)
	if e := s.ClaimCreation(start, a); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s = open(t, dir)
	defer s.Close()
	if _, e := s.FenceNeverStarted(start, fence, a, key, time.Now()); e != ErrCreationClaimed {
		t.Fatalf("expected retained uncertainty, got %v", e)
	}
	if e := s.ClaimCreation(start, a); e == nil {
		t.Fatal("duplicate runtime create allowed")
	}
}
func TestCreationAndFenceRaceNeverBothSucceed(t *testing.T) {
	for n := 0; n < 20; n++ {
		start, fence, a, key := fixture(t)
		s := open(t, t.TempDir())
		var createErr, fenceErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); createErr = s.ClaimCreation(start, a) }()
		go func() { defer wg.Done(); _, fenceErr = s.FenceNeverStarted(start, fence, a, key, time.Now()) }()
		wg.Wait()
		s.Close()
		if createErr == nil && fenceErr == nil {
			t.Fatal("creation and never-started proof both authorized")
		}
	}
}
func TestCorruptOrConflictingJournalAndWrongFenceFailClosed(t *testing.T) {
	start, fence, a, key := fixture(t)
	dir := t.TempDir()
	s := open(t, dir)
	defer s.Close()
	bad := a
	bad.HostID = "wrong-host"
	if _, e := s.FenceNeverStarted(start, fence, bad, key, time.Now()); e == nil {
		t.Fatal("wrong host accepted")
	}
	if _, e := s.FenceNeverStarted(start, fence, a, key, time.Now()); e != nil {
		t.Fatal(e)
	}
	entries, _ := filepath.Glob(filepath.Join(dir, "*.creation.json"))
	if len(entries) != 1 {
		t.Fatal("missing marker")
	}
	if e := os.WriteFile(entries[0], []byte("{partial"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.FenceNeverStarted(start, fence, a, key, time.Now()); e == nil {
		t.Fatal("corrupt marker produced proof")
	}
	if e := s.ClaimCreation(start, a); e == nil {
		t.Fatal("corrupt marker allowed creation")
	}
}
func TestExclusiveProcessLock(t *testing.T) {
	s := open(t, t.TempDir())
	defer s.Close()
	if second, e := Open(s.path); e == nil {
		second.Close()
		t.Fatal("two journal owners")
	}
}
