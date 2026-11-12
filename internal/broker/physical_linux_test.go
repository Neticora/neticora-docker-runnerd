//go:build linux

package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

type componentRuntime struct {
	endpoint                               string
	objects                                map[string]dockerengine.Object
	names                                  map[string]string
	creates, starts, stops, removes, pulls int
	lostCreate                             bool
	lostRemove                             bool
	peerChanged                            bool
	networkAttached                        bool
}

func (f *componentRuntime) RecoveryDomain(context.Context) (string, error) {
	if f.peerChanged {
		return "", dockerengine.ErrUnavailable
	}
	return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil
}
func (f *componentRuntime) VerifyRecoveryNetworkDetached(ctx context.Context, id, name, network string) error {
	return f.VerifyNetworkDetached(ctx, id, network)
}

func (f *componentRuntime) VerifyNetworkDetached(context.Context, string, string) error {
	if f.networkAttached {
		return dockerengine.ErrConflict
	}
	return nil
}

func (f *componentRuntime) Probe(context.Context) (string, error) {
	if f.peerChanged {
		return "replaced", nil
	}
	return f.endpoint, nil
}
func (f *componentRuntime) PrepareImageAuthorized(_ context.Context, _ dockerengine.Plan, allow func() error) error {
	if err := allow(); err != nil {
		return err
	}
	f.pulls++
	return nil
}
func (f *componentRuntime) Inspect(_ context.Context, id string, _ dockerengine.Plan) (dockerengine.Object, error) {
	if resolved := f.names[id]; resolved != "" {
		id = resolved
	}
	object, ok := f.objects[id]
	if !ok {
		return dockerengine.Object{}, dockerengine.ErrAbsent
	}
	return object, nil
}
func (f *componentRuntime) Ensure(_ context.Context, p dockerengine.Plan, claim func() error) (dockerengine.Object, error) {
	if err := claim(); err != nil {
		return dockerengine.Object{}, err
	}
	f.creates++
	hash := sha256.Sum256([]byte(p.Name))
	id := hex.EncodeToString(hash[:])
	o := dockerengine.Object{ID: id, State: "prepared"}
	f.objects[id] = o
	f.names[p.Name] = id
	if f.lostCreate {
		return dockerengine.Object{}, dockerengine.ErrUnavailable
	}
	return o, nil
}
func (f *componentRuntime) Start(_ context.Context, id string, _ dockerengine.Plan, allow func() error) (dockerengine.Object, error) {
	if err := allow(); err != nil {
		return dockerengine.Object{}, err
	}
	f.starts++
	o := f.objects[id]
	o.State = "running"
	f.objects[id] = o
	return o, nil
}
func (f *componentRuntime) Stop(_ context.Context, id string, _ dockerengine.Plan) error {
	f.stops++
	o := f.objects[id]
	o.State = "exited"
	f.objects[id] = o
	return nil
}
func (f *componentRuntime) Remove(_ context.Context, id string, _ dockerengine.Plan) error {
	f.removes++
	delete(f.objects, id)
	if f.lostRemove {
		return dockerengine.ErrUnavailable
	}
	return nil
}
func (f *componentRuntime) Inventory(context.Context) ([]string, error) {
	var ids []string
	for id := range f.objects {
		ids = append(ids, id)
	}
	return ids, nil
}

func physicalFixture(t *testing.T) (*physicalExecutor, *componentRuntime, SignedExecutionGrant, ed25519.PrivateKey, time.Time) {
	t.Helper()
	_, signed, key, private, now := executionFixture(t, "PrepareImage")
	l, _ := testLedger(t)
	raw, err := os.ReadFile("../../api/fixtures/validation.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID    string         `json:"id"`
		Value map[string]any `json:"value"`
	}
	_ = json.Unmarshal(raw, &cases)
	var policy *standardlinux.Policy
	for _, c := range cases {
		if c.ID == "customer-managed-policy-1.1" {
			c.Value["allowedTenantIds"] = []string{signed.Grant.Binding.TenantID}
			data, _ := json.Marshal(c.Value)
			policy, err = standardlinux.ParsePolicy(data, nil)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if policy == nil {
		t.Fatal("missing policy fixture")
	}
	runtime := &componentRuntime{endpoint: signed.Grant.Binding.EndpointIdentity, objects: map[string]dockerengine.Object{}, names: map[string]string{}}
	e := &physicalExecutor{ledger: l, runtime: runtime, key: key, scope: signed.Grant.Binding, policy: policy, boot: "original-test-boot", now: func() time.Time { return now },
		settings: standardlinux.Settings{ImageRepository: "example/runner", NetworkID: "approved-network", BootstrapRoot: "/run/broker-component-handoff", RunnerUID: 1000, PidsLimit: 128}}
	// These are explicit component fixtures, not signature/mount confinement or
	// real Docker qualification. Shipping activation must supply verified guards.
	e.verifyImage = func(context.Context, protocol.ExecutionSpec) error { return nil }
	e.guardMounts = func(context.Context, dockerengine.Plan) error { return nil }
	return e, runtime, signed, private, now
}

func physicalAuthorization(t *testing.T, e *physicalExecutor, base SignedExecutionGrant, private ed25519.PrivateKey, action string, revision int, resource string) (ExecutionGrantRequest, SignedExecutionGrant, SignedCommit) {
	t.Helper()
	r := ExecutionGrantRequest{Version: ExecutionGrantVersion, Operation: action, ExecutionID: base.Grant.Binding.ExecutionID, Generation: base.Grant.Binding.Generation, ExpectedRevision: strconv.Itoa(revision), ResourceID: resource}
	r.OperationID = r.OperationIdentity()
	s := base
	s.Grant.Operation = action
	s.Grant.OperationID = r.OperationID
	s.Grant.ExpectedRevision = r.ExpectedRevision
	s.Grant.ExpectedState = executionState(action)
	s.Grant.ResourceID = resource
	c := freshChallenge(t, e.ledger, &r, &s, private, e.now())
	return r, s, c
}

func TestPhysicalStandardLifecycleComponent(t *testing.T) {
	e, runtime, base, key, _ := physicalFixture(t)
	ctx := context.Background()
	resource := ""
	for revision, action := range []string{"PrepareImage", "CreateExecution", "StartExecution", "StopExecution", "RemoveExecution"} {
		r, s, c := physicalAuthorization(t, e, base, key, action, revision, resource)
		o, err := e.Execute(ctx, r, s, c)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if action == "CreateExecution" {
			resource = o.ID
		}
		before := []int{runtime.pulls, runtime.creates, runtime.starts, runtime.stops, runtime.removes}
		if _, err = e.Execute(ctx, r, s, c); err != nil {
			t.Fatalf("historical duplicate %s: %v", action, err)
		}
		after := []int{runtime.pulls, runtime.creates, runtime.starts, runtime.stops, runtime.removes}
		for i := range before {
			if before[i] != after[i] {
				t.Fatal("duplicate repeated physical effect")
			}
		}
	}
	if runtime.creates != 1 || runtime.starts != 1 || runtime.stops != 1 || runtime.removes != 1 || len(runtime.objects) != 0 {
		t.Fatal("lifecycle not exact-once")
	}
	root, err := e.ledger.records("resources")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var record physicalRecord
	if err = readRecord(root, recordID(base.Grant.Binding), &record); err != nil {
		t.Fatal(err)
	}
	if record.State != "REMOVED" || record.Revision != "5" || !record.CancelFence || record.ResourceID != resource {
		t.Fatal("ownership/fence lost")
	}
}

func TestPhysicalLostCreateQuarantinesWithoutReplacement(t *testing.T) {
	e, runtime, base, key, _ := physicalFixture(t)
	runtime.lostCreate = true
	r, s, c := physicalAuthorization(t, e, base, key, "CreateExecution", 0, "")
	if _, err := e.Execute(context.Background(), r, s, c); !errors.Is(err, ErrQuarantined) {
		t.Fatal(err)
	}
	if _, err := e.Execute(context.Background(), r, s, c); !errors.Is(err, ErrQuarantined) {
		t.Fatal("uncertain create was repeated", err)
	}
	if runtime.creates != 1 || len(runtime.objects) != 1 {
		t.Fatal("original resource replaced")
	}
	root, err := e.ledger.records("resources")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var record physicalRecord
	if err = readRecord(root, recordID(base.Grant.Binding), &record); err != nil {
		t.Fatal(err)
	}
	if record.State != "QUARANTINED" || record.Pending != r.OperationID || record.Binding != base.Grant.Binding {
		t.Fatal("recovery obligation lost")
	}
}

func TestPhysicalRejectsForgedRevisionForeignAdoptionAndPeerReplacement(t *testing.T) {
	for _, scenario := range []string{"revision", "foreign", "peer", "mount-guard"} {
		t.Run(scenario, func(t *testing.T) {
			e, runtime, base, key, _ := physicalFixture(t)
			revision := 0
			if scenario == "revision" {
				revision = 1
			}
			r, s, c := physicalAuthorization(t, e, base, key, "CreateExecution", revision, "")
			if scenario == "foreign" {
				p, _ := e.settings.Plan(agent.StoreScope{InstallationID: e.scope.InstallationID, TenantID: e.scope.TenantID, HostID: e.scope.HostID, EndpointIdentity: e.scope.EndpointIdentity}, base.Grant.Spec)
				runtime.names[p.Name] = "foreign"
				runtime.objects["foreign"] = dockerengine.Object{ID: "foreign", State: "prepared"}
			}
			if scenario == "peer" {
				runtime.peerChanged = true
			}
			if scenario == "mount-guard" {
				e.guardMounts = func(context.Context, dockerengine.Plan) error { return ErrRejected }
			}
			if _, err := e.Execute(context.Background(), r, s, c); err == nil || runtime.creates != 0 {
				t.Fatal("unowned/unsafe create allowed")
			}
		})
	}
}

func TestPhysicalOwnershipCancellationAndRebootGuards(t *testing.T) {
	for _, scenario := range []string{"cross-execution-target", "stale-revision", "cancel-before-start", "reboot", "plan-change", "expired-after-probe"} {
		t.Run(scenario, func(t *testing.T) {
			e, runtime, base, key, now := physicalFixture(t)
			r, s, c := physicalAuthorization(t, e, base, key, "CreateExecution", 0, "")
			o, err := e.Execute(context.Background(), r, s, c)
			if err != nil {
				t.Fatal(err)
			}
			action, revision, target := "StartExecution", 1, o.ID
			switch scenario {
			case "cross-execution-target":
				action = "StopExecution"
				target = strings.Repeat("f", 64)
				runtime.objects[target] = dockerengine.Object{ID: target, State: "running"}
			case "stale-revision":
				revision = 0
			case "cancel-before-start":
				q, g, commit := physicalAuthorization(t, e, base, key, "StopExecution", 1, o.ID)
				if _, err = e.Execute(context.Background(), q, g, commit); err != nil {
					t.Fatal(err)
				}
				revision = 2
			case "reboot":
				e.boot = "new-boot"
			case "plan-change":
				e.settings.ImageRepository = "other/runner"
			case "expired-after-probe":
				e.guardMounts = func(context.Context, dockerengine.Plan) error {
					e.now = func() time.Time { return now.Add(20 * time.Second) }
					return nil
				}
			}
			r, s, c = physicalAuthorization(t, e, base, key, action, revision, target)
			if _, err = e.Execute(context.Background(), r, s, c); err == nil {
				t.Fatal("unsafe mutation accepted")
			}
			if runtime.starts != 0 || runtime.removes != 0 || (scenario == "cross-execution-target" && runtime.stops != 0) {
				t.Fatal("unrelated/stale resource mutated")
			}
		})
	}
}

func TestPhysicalLostRemoveNeverReportsCleanedOrRepeatsEffect(t *testing.T) {
	e, runtime, base, key, _ := physicalFixture(t)
	resource := ""
	for revision, action := range []string{"CreateExecution", "StartExecution", "StopExecution"} {
		r, s, c := physicalAuthorization(t, e, base, key, action, revision, resource)
		o, err := e.Execute(context.Background(), r, s, c)
		if err != nil {
			t.Fatal(err)
		}
		resource = o.ID
	}
	runtime.lostRemove = true
	r, s, c := physicalAuthorization(t, e, base, key, "RemoveExecution", 3, resource)
	if _, err := e.Execute(context.Background(), r, s, c); !errors.Is(err, ErrQuarantined) {
		t.Fatal(err)
	}
	if _, err := e.Execute(context.Background(), r, s, c); !errors.Is(err, ErrQuarantined) {
		t.Fatal(err)
	}
	root, err := e.ledger.records("resources")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var state physicalRecord
	if err = readRecord(root, recordID(base.Grant.Binding), &state); err != nil {
		t.Fatal(err)
	}
	if runtime.removes != 1 || state.State != "QUARANTINED" || state.ResourceID != resource || state.Pending != r.OperationID {
		t.Fatal("ambiguous removal erased obligation")
	}
}
