//go:build linux

package broker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

type componentKata struct {
	executor                               *physicalExecutor
	t                                      *testing.T
	prepare, prepared, captures, disposals int
	gone                                   bool
	denyCapture                            bool
}

func (k *componentKata) Plan(scope agent.StoreScope, s protocol.ExecutionSpec) (dockerengine.Plan, error) {
	return k.executor.settings.Plan(scope, s)
}
func (*componentKata) Admit(context.Context, agent.StoreScope, protocol.ExecutionSpec, *standardlinux.Policy, time.Time) error {
	return nil
}
func (k *componentKata) Prepare(_ context.Context, p dockerengine.Plan) error {
	// Allocation must follow both consumed authorization and durable intent.
	q := Lookup{ExecutionID: p.Config.Labels[dockerengine.LabelPrefix+"execution"], Generation: p.Config.Labels[dockerengine.LabelPrefix+"generation"], SpecHash: p.Config.Labels[dockerengine.LabelPrefix+"spec"]}
	state, _, err := k.executor.load(q)
	if err != nil || state.Pending == "" || state.Operations["CreateExecution"].OperationID != state.Pending {
		k.t.Fatal("Kata allocation without durable create intent", err)
	}
	if _, err = k.executor.ledger.read(state.Pending); err != nil {
		k.t.Fatal("Kata allocation without receipt", err)
	}
	k.prepare++
	return nil
}
func (k *componentKata) Prepared(string, dockerengine.Plan) error             { k.prepared++; return nil }
func (*componentKata) VerifyStorage(context.Context, dockerengine.Plan) error { return nil }
func (k *componentKata) Capture(context.Context, string, dockerengine.Plan) error {
	if k.denyCapture {
		return ErrQuarantined
	}
	k.captures++
	return nil
}
func (*componentKata) Healthy(dockerengine.Plan, string, time.Time) bool { return true }
func (k *componentKata) Dispose(_ context.Context, _ string, _ dockerengine.Plan, guard func() error) error {
	if err := guard(); err != nil {
		return err
	}
	k.disposals++
	k.gone = true
	return nil
}
func (k *componentKata) Absence(context.Context, string, dockerengine.Plan) error {
	if !k.gone {
		return ErrQuarantined
	}
	return nil
}
func (*componentKata) Evidence(context.Context, string, dockerengine.Plan) (json.RawMessage, error) {
	return nil, ErrRejected
}
func isolatedFixture(t *testing.T) (*physicalExecutor, *componentRuntime, SignedExecutionGrant, *componentKata) {
	e, r, s, _, _ := physicalFixture(t)
	s.Grant.Spec.IsolationProfile = "isolated"
	s.Grant.Spec.TemplateVersion = "linux-github-kata-v2"
	s.Grant.Spec.ProfileVersion = "docker-kata-rs-qemu-v3-" + strings.Repeat("a", 64)
	raw, _ := json.Marshal(s.Grant.Spec)
	s.Grant.Spec.SpecHash, _ = protocol.PayloadHashJSON("ExecutionSpec", raw)
	s.Grant.Binding.SpecHash = s.Grant.Spec.SpecHash
	e.scope.SpecHash = s.Grant.Spec.SpecHash
	k := &componentKata{executor: e, t: t}
	e.kata = k
	return e, r, s, k
}
func TestKataGrantRequiresProtectedProfile(t *testing.T) {
	e, r, s, _ := isolatedFixture(t)
	_, _, _, key, _ := executionFixture(t, "PrepareImage")
	// Use a matching independent signing key, never controller credentials.
	e.key = key.Public().(ed25519.PublicKey)
	e.kata = nil
	q, g, c := physicalAuthorization(t, e, s, key, "PrepareImage", 0, "")
	if _, err := e.Execute(context.Background(), q, g, c); !errors.Is(err, ErrRejected) {
		t.Fatal("isolated grant without protected tuple accepted", err)
	}
	if r.pulls != 0 || r.creates != 0 {
		t.Fatal("unauthorized runtime effect")
	}
}
func TestKataLifecycleConsumesOnceAndRetainsStorageObligation(t *testing.T) {
	e, r, s, k := isolatedFixture(t)
	_, _, _, key, _ := executionFixture(t, "PrepareImage")
	e.key = key.Public().(ed25519.PublicKey)
	id := ""
	for revision, action := range []string{"PrepareImage", "CreateExecution", "StartExecution", "StopExecution", "RemoveExecution"} {
		q, g, c := physicalAuthorization(t, e, s, key, action, revision, id)
		o, err := e.Execute(context.Background(), q, g, c)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if action == "CreateExecution" {
			id = o.ID
		}
		if _, err = e.Execute(context.Background(), q, g, c); err != nil {
			t.Fatal(err)
		}
	}
	if r.creates != 1 || r.starts != 1 || k.prepare != 1 || k.disposals != 1 || k.prepared < 1 || k.captures < 1 {
		t.Fatal("Kata original effects repeated or omitted", k, r)
	}
	q := Lookup{ExecutionID: s.Grant.Binding.ExecutionID, Generation: s.Grant.Binding.Generation, SpecHash: s.Grant.Binding.SpecHash, ResourceID: id}
	k.gone = false
	if _, err := e.State(context.Background(), q, true); !errors.Is(err, ErrQuarantined) {
		t.Fatal("Docker absence released unresolved Kata storage", err)
	}
	if _, err := e.IssueBootChallenge(context.Background(), q, key); !errors.Is(err, ErrQuarantined) {
		t.Fatal("Docker-only boot grant accepted for Kata", err)
	}
}

func (*componentKata) Check(context.Context) (string, error) { return "component-kata", nil }

func TestKataPreflightOnlyObservesProtectedProfile(t *testing.T) {
	e, r, _, _ := isolatedFixture(t)
	h := handler{config: Config{ControllerUID: 1000}, executor: e}
	call := func(q Request) (int, Response) {
		raw, _ := json.Marshal(q)
		request := httptest.NewRequest(http.MethodPost, "/v1/request", bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(context.WithValue(request.Context(), caller{}, uint32(1000)))
		reply := httptest.NewRecorder()
		h.ServeHTTP(reply, request)
		var response Response
		json.Unmarshal(reply.Body.Bytes(), &response)
		return reply.Code, response
	}
	q := Request{Version: Version, Operation: "CheckKataProfile"}
	status, response := call(q)
	if status != 200 || response.KataProfile != "component-kata" || response.Endpoint != e.scope.EndpointIdentity {
		t.Fatal("protected profile not observed", status, response)
	}
	q.Target = "controller-selected-profile"
	if status, _ := call(q); status == 200 {
		t.Fatal("caller-selected profile accepted")
	}
	q.Target = ""
	q.MinimumFreeBytes = 1
	if status, _ := call(q); status == 200 {
		t.Fatal("unexpected preflight payload accepted")
	}
	q.MinimumFreeBytes = 0
	e.kata = nil
	if status, _ := call(q); status == 200 {
		t.Fatal("unconfigured Kata profile inferred")
	}
	if r.pulls+r.creates+r.starts+r.stops+r.removes != 0 {
		t.Fatal("read-only preflight mutated runtime")
	}
}
