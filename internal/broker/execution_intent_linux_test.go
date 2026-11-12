//go:build linux

package broker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testCommit(t *testing.T, s SignedExecutionGrant, private ed25519.PrivateKey, now time.Time) SignedCommit {
	t.Helper()
	c := SignedCommit{Commit: Commit{Version: commitVersion, Audience: s.Grant.Audience, OperationID: s.Grant.OperationID, GrantHash: signedGrantHash(s), Challenge: s.Grant.Challenge, Binding: s.Grant.Binding, State: "COMMITTED", NotBefore: now.UTC().Format(time.RFC3339Nano), ExpiresAt: s.Grant.ExpiresAt}}
	raw, err := canonical(c.Commit)
	if err != nil {
		t.Fatal(err)
	}
	c.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(commitDomain), raw...)))
	return c
}

func freshChallenge(t *testing.T, l *Ledger, r *ExecutionGrantRequest, s *SignedExecutionGrant, key ed25519.PrivateKey, now time.Time) SignedCommit {
	t.Helper()
	r.Challenge = ""
	c, err := l.IssueChallenge(*r, now)
	if err != nil {
		t.Fatal(err)
	}
	*r = c.Request
	s.Grant.Challenge = r.Challenge
	signExecution(t, s, key)
	return testCommit(t, *s, key, now)
}

func TestExecutionIntentReplayAndCancellationFence(t *testing.T) {
	l, _ := testLedger(t)
	r, s, key, private, now := executionFixture(t, "StartExecution")
	commit := freshChallenge(t, l, &r, &s, private, now)
	first, duplicate, err := l.AcceptExecutionIntent(s, r, key, testBinding(), now, commit)
	if err != nil || duplicate {
		t.Fatalf("first acceptance %v %v", duplicate, err)
	}
	second, duplicate, err := l.AcceptExecutionIntent(s, r, key, testBinding(), now, commit)
	if err != nil || !duplicate || first != second {
		t.Fatalf("replay changed intent %v %v", duplicate, err)
	}
	// Consumption is permanent: a new cycle cannot reauthorize this effect.
	again := r
	again.Challenge = ""
	if _, err = l.IssueChallenge(again, now); err == nil {
		t.Fatal("consumed operation reauthorized")
	}
	// Authenticated stop becomes a permanent no-new-launch fence, surviving replay
	// of a previously valid start grant. No stop runtime effect is claimed here.
	r.Operation = "StopExecution"
	r.OperationID = r.OperationIdentity()
	s.Grant.Operation = r.Operation
	s.Grant.OperationID = r.OperationID
	s.Grant.ExpectedState = executionState(r.Operation)
	signExecution(t, &s, private)
	commit = freshChallenge(t, l, &r, &s, private, now)
	if _, _, err = l.AcceptExecutionIntent(s, r, key, testBinding(), now, commit); err != nil {
		t.Fatal(err)
	}
	r.Operation = "StartExecution"
	r.OperationID = r.OperationIdentity()
	s.Grant.Operation = r.Operation
	s.Grant.OperationID = r.OperationID
	s.Grant.ExpectedState = executionState(r.Operation)
	signExecution(t, &s, private)
	if _, _, err = l.AcceptExecutionIntent(s, r, key, testBinding(), now, testCommit(t, s, private, now)); err == nil {
		t.Fatal("cancelled execution accepted old start grant")
	}
}

func TestExecutionAuthorizationIPCRequiresIndependentKey(t *testing.T) {
	l, _ := testLedger(t)
	r, s, key, private, now := executionFixture(t, "PrepareImage")
	commit := freshChallenge(t, l, &r, &s, private, now)
	h := handler{config: Config{ControllerUID: 1234, Scope: testBinding()}, executionKey: key, ledger: l}
	request := Request{Version: Version, Operation: "AuthorizeExecution", ExecutionRequest: &r, ExecutionGrant: &s, ExecutionCommit: &commit}
	call := func(uid uint32) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(request)
		req := httptest.NewRequest(http.MethodPost, "/v1/request", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(context.WithValue(req.Context(), caller{}, uid))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if w := call(1235); w.Code != 403 {
		t.Fatal("wrong peer accepted")
	}
	if w := call(1234); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := call(1234); w.Code != 200 {
		t.Fatal("idempotent duplicate failed")
	}
	h.executionKey = nil
	if w := call(1234); w.Code != 403 {
		t.Fatal("matching peer UID substituted for platform authority")
	}
}
