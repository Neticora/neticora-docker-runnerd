//go:build linux

package execution

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	"github.com/Neticora/neticora-docker-runnerd/journal"
	"github.com/oapi-codegen/nullable"
)

type fakeRuntime struct {
	object                            *dockerengine.Object
	creates, starts, stops, removes   int
	lostCreate, disconnectAfterRemove bool
	afterEnsure, beforeStart          func()
}

func (f *fakeRuntime) Probe(context.Context) (string, error) {
	if f.disconnectAfterRemove && f.removes > 0 {
		return "", dockerengine.ErrUnavailable
	}
	return "engine-a", nil
}
func (f *fakeRuntime) Inventory(context.Context) ([]string, error) {
	if f.object == nil {
		return []string{}, nil
	}
	return []string{f.object.ID}, nil
}
func (f *fakeRuntime) Inspect(context.Context, string, dockerengine.Plan) (dockerengine.Object, error) {
	if f.object == nil {
		return dockerengine.Object{}, dockerengine.ErrAbsent
	}
	return *f.object, nil
}
func (f *fakeRuntime) PrepareImage(context.Context, dockerengine.Plan) error { return nil }
func (f *fakeRuntime) Ensure(_ context.Context, _ dockerengine.Plan, claim func() error) (dockerengine.Object, error) {
	if f.object != nil {
		return *f.object, nil
	}
	if err := claim(); err != nil {
		return dockerengine.Object{}, err
	}
	f.creates++
	f.object = &dockerengine.Object{ID: strings.Repeat("c", 64), State: "prepared"}
	if f.lostCreate {
		return dockerengine.Object{}, dockerengine.ErrUnavailable
	}
	if f.afterEnsure != nil {
		f.afterEnsure()
	}
	return *f.object, nil
}
func (f *fakeRuntime) Start(_ context.Context, _ string, _ dockerengine.Plan, authorize func() error) (dockerengine.Object, error) {
	if err := authorize(); err != nil {
		return dockerengine.Object{}, err
	}
	if f.beforeStart != nil {
		f.beforeStart()
	}
	f.starts++
	f.object.State = "running"
	return *f.object, nil
}
func (f *fakeRuntime) Stop(context.Context, string, dockerengine.Plan) error {
	f.stops++
	if f.object != nil {
		f.object.State = "exited"
	}
	return nil
}
func (f *fakeRuntime) Remove(context.Context, string, dockerengine.Plan) error {
	f.removes++
	f.object = nil
	return nil
}
func (f *fakeRuntime) Watch(ctx context.Context, _ func()) error { <-ctx.Done(); return ctx.Err() }

type fakeRemote struct {
	expires         string
	t               *testing.T
	start           protocol.StartCommand
	inventory       string
	deny            bool
	requests        [][]byte
	recoveryEntries []protocol.RecoveryEntry
	lookups         [][]agent.ExecutionCursor
}

func (f *fakeRemote) Recovery(_ context.Context, lookups []agent.ExecutionCursor) (protocol.RecoveryState, error) {
	f.lookups = append(f.lookups, append([]agent.ExecutionCursor(nil), lookups...))
	entries := f.recoveryEntries
	if entries == nil {
		entries = []protocol.RecoveryEntry{{ExecutionId: f.start.Spec.ExecutionId, Generation: f.start.Generation, CommandId: f.start.CommandId, SpecHash: f.start.Spec.SpecHash, ContiguousSequence: "0"}}
	}
	return protocol.RecoveryState{Identity: protocol.HostIdentity{HostId: "host-a", KeyId: "key-a", KeyVersion: "1", SessionEpoch: "1"}, EndpointIdentity: "engine-a", InventoryGeneration: f.inventory, Entries: entries}, nil
}
func (f *fakeRemote) Commands(context.Context) ([]json.RawMessage, error) { return nil, nil }
func (f *fakeRemote) Ack(context.Context, agent.Receipt) error            { return nil }
func (f *fakeRemote) Inventory(_ context.Context, m protocol.Outbound) error {
	var snapshot protocol.InventorySnapshot
	_ = json.Unmarshal(m.Bytes(), &snapshot)
	f.inventory = snapshot.InventoryGeneration
	return nil
}
func (f *fakeRemote) Events(context.Context, protocol.Outbound) ([]protocol.EventAck, error) {
	return nil, nil
}
func (f *fakeRemote) Admission(context.Context, protocol.ExecutionSpec) error {
	if f.deny {
		return ErrReconcile
	}
	return nil
}
func (f *fakeRemote) Heartbeat(context.Context, string) error { return nil }
func (f *fakeRemote) Start(_ context.Context, m protocol.Outbound) (protocol.StartResponse, error) {
	if f.deny {
		return protocol.StartResponse{}, ErrReconcile
	}
	f.requests = append(f.requests, m.Bytes())
	var req protocol.StartRequest
	_ = json.Unmarshal(m.Bytes(), &req)
	if f.expires == "" {
		f.expires = time.Now().Add(60 * time.Second).UTC().Format(wireTime)
	}
	expires := f.expires
	peerRaw, _ := base64.RawURLEncoding.DecodeString(*req.BootstrapPublicKey)
	peer, _ := ecdh.X25519().NewPublicKey(peerRaw)
	private, _ := ecdh.X25519().GenerateKey(rand.Reader)
	secret, _ := private.ECDH(peer)
	envelope := map[string]any{"version": "runnerd05-sealed-v1", "tenantId": "tenant-a", "hostId": "host-a", "executionId": req.ExecutionId, "generation": req.Generation, "startRequestId": req.StartRequestId, "specHash": req.SpecHash, "expiresAt": expires, "recipient": *req.BootstrapPublicKey, "ephemeral": base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())}
	raw, _ := json.Marshal(envelope)
	aad, _ := protocol.CanonicalizeJSON(raw)
	salt := sha256.Sum256(aad)
	key, _ := hkdf.Key(sha256.New, secret, salt[:], "neticora-runnerd-bootstrap-v1", 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	envelope["nonce"] = base64.RawURLEncoding.EncodeToString(nonce)
	envelope["ciphertext"] = base64.RawURLEncoding.EncodeToString(gcm.Seal(nil, nonce, []byte("CANARY-JIT"), aad))
	raw, _ = json.Marshal(envelope)
	deliveryTime, _ := time.Parse(time.RFC3339Nano, expires)
	providerExpiry := deliveryTime.Add(4 * time.Minute).UTC().Format(wireTime)
	return protocol.StartResponse{State: "ISSUED", IssuanceId: "issuance-a", BootstrapExpiresAt: &providerExpiry, RecoveryExpiresAt: &expires, EncryptedBootstrap: nullable.NewNullableWithValue(base64.RawURLEncoding.EncodeToString(raw))}, nil
}

func setup(t *testing.T) (*Controller, *fakeRuntime, *fakeRemote, agent.Execution) {
	t.Helper()
	ctx := context.Background()
	dir := func() string {
		d := t.TempDir()
		if err := os.Chmod(d, 0700); err != nil {
			t.Fatal(err)
		}
		return d
	}
	s, err := journal.OpenRecovery(ctx, dir(), journal.Options{ReservationLimits: agent.ReservationLimits{CPUMillis: 1000, MemoryBytes: 1073741824, StorageBytes: 10737418240, Slots: 1}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	storetest.Reconcile(t, s, storetest.Scope, "1")
	command := storetest.Object(t, storetest.Start(t, "a"))
	command["spec"].(map[string]any)["templateVersion"] = standardlinux.TemplateVersion
	raw := storetest.Encode(t, "HostCommand", command)
	var start protocol.StartCommand
	_ = json.Unmarshal(raw, &start)
	if _, err = s.AcceptCommand(ctx, storetest.Scope, raw); err != nil {
		t.Fatal(err)
	}
	fixtures, err := os.ReadFile("../../api/fixtures/validation.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID    string          `json:"id"`
		Value json.RawMessage `json:"value"`
	}
	_ = json.Unmarshal(fixtures, &cases)
	var policy *standardlinux.Policy
	for _, c := range cases {
		if c.ID == "customer-managed-policy-1.1" {
			policy, err = standardlinux.ParsePolicy(c.Value, nil)
		}
	}
	if err != nil || policy == nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{}
	remote := &fakeRemote{t: t, start: start, inventory: "1"}
	c := &Controller{Store: s, Runtime: runtime, Remote: remote, Scope: storetest.Scope, Authority: journal.Authority{TenantID: "tenant-a", HostID: "host-a", SessionEpoch: "1", EndpointIdentity: "engine-a", KeyID: "key-a"}, Profile: standardlinux.Settings{ImageRepository: "example/runner", NetworkID: "customer-network", BootstrapRoot: dir(), RunnerUID: 1000, PidsLimit: 128}, Policy: func() *standardlinux.Policy { return policy }, VerifyImage: func(context.Context, *standardlinux.Policy, string, string, time.Time) error { return nil }, KeysDirectory: dir(), Organization: "Neticora", Pool: "pool-a", Drained: func() bool { return false }, cancelled: map[agent.ExecutionCursor]bool{}}
	rows, err := s.Incomplete(ctx, agent.ExecutionCursor{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	return c, runtime, remote, rows[0]
}
func current(t *testing.T, c *Controller) agent.Execution {
	t.Helper()
	rows, err := c.Store.Executions(context.Background(), agent.ExecutionCursor{}, 100)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	return rows[0]
}

func TestLaunchPersistsIntentAndEventsAndNeverRepeatsAttempt(t *testing.T) {
	c, r, remote, e := setup(t)
	if err := c.execution(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	e = current(t, c)
	if r.creates != 1 || r.starts != 1 || e.State != "running" || e.LastSequence != "2" || len(e.StartRequest) == 0 {
		t.Fatalf("incomplete launch: %+v", e)
	}
	for i := 0; i < 3; i++ {
		if err := c.execution(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	if r.creates != 1 || r.starts != 1 {
		t.Fatal("attempt reran")
	}
	for _, raw := range remote.requests {
		if string(raw) != string(e.StartRequest) {
			t.Fatal("issuance request changed")
		}
	}
	events, err := c.Store.PendingEvents(context.Background(), agent.EventPage{ExecutionID: e.Identity.ExecutionID, Generation: "1", AfterSequence: "0", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range events {
		if strings.Contains(string(raw), "CANARY-JIT") {
			t.Fatal("bootstrap leaked into journal")
		}
	}
}

func TestLaunchBindsSealedHandoffToEarlierRecoveryDeadline(t *testing.T) {
	c, runtime, remote, e := setup(t)
	if err := c.execution(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	p, err := c.plan(e)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(c.Profile.BootstrapRoot, p.Name, "bootstrap.json"))
	if err != nil {
		t.Fatal(err)
	}
	var handoff struct {
		ExpiresAt string `json:"expiresAt"`
	}
	if err = json.Unmarshal(raw, &handoff); err != nil {
		t.Fatal(err)
	}
	if handoff.ExpiresAt != remote.expires || runtime.starts != 1 {
		t.Fatal("handoff did not retain sealed recovery deadline")
	}
}

type alteredStartRemote struct {
	*fakeRemote
	alter func(*protocol.StartResponse)
}

func (f alteredStartRemote) Start(ctx context.Context, m protocol.Outbound) (protocol.StartResponse, error) {
	r, e := f.fakeRemote.Start(ctx, m)
	if e == nil {
		f.alter(&r)
	}
	return r, e
}

func TestInvalidRecoveryDeadlinesNeverCreateOrStart(t *testing.T) {
	for _, mode := range []string{"missing", "expired", "after-bootstrap", "after-authority"} {
		t.Run(mode, func(t *testing.T) {
			c, r, remote, e := setup(t)
			c.Remote = alteredStartRemote{remote, func(response *protocol.StartResponse) {
				if mode == "missing" {
					response.RecoveryExpiresAt = nil
					return
				}
				value := time.Now().Add(-time.Minute).UTC().Format(wireTime)
				if mode == "after-bootstrap" {
					value = time.Now().Add(10 * time.Minute).UTC().Format(wireTime)
				}
				if mode == "after-authority" {
					value = time.Now().Add(48 * time.Hour).UTC().Format(wireTime)
					provider := time.Now().Add(72 * time.Hour).UTC().Format(wireTime)
					response.BootstrapExpiresAt = &provider
				}
				response.RecoveryExpiresAt = &value
			}}
			if err := c.execution(context.Background(), e); err == nil || r.creates != 0 || r.starts != 0 {
				t.Fatal("invalid delivery authority launched work", err)
			}
		})
	}
}

func TestLostCreateReplyAdoptsCreatedObjectWithSameIntent(t *testing.T) {
	c, r, _, e := setup(t)
	r.lostCreate = true
	if err := c.execution(context.Background(), e); !errors.Is(err, dockerengine.ErrUnavailable) {
		t.Fatal(err)
	}
	if err := c.execution(context.Background(), current(t, c)); err != nil {
		t.Fatal(err)
	}
	if err := c.execution(context.Background(), current(t, c)); err != nil {
		t.Fatal(err)
	}
	if r.creates != 1 || r.starts != 1 {
		t.Fatalf("creates=%d starts=%d", r.creates, r.starts)
	}
}

func TestCancellationAndBadSignaturesNeverLaunch(t *testing.T) {
	for _, scenario := range []string{"signature", "policy", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			c, r, remote, e := setup(t)
			if scenario == "signature" {
				c.VerifyImage = func(context.Context, *standardlinux.Policy, string, string, time.Time) error {
					return standardlinux.ErrAdmission
				}
			}
			if scenario == "policy" {
				remote.deny = true
			}
			if scenario == "cancel" {
				command := storetest.Encode(t, "HostCommand", map[string]any{"commandId": "cancel-a", "kind": "cancel", "executionId": e.Identity.ExecutionID, "generation": "1"})
				if _, err := c.Store.AcceptCommand(context.Background(), c.Scope, command); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.execution(context.Background(), e); err == nil || r.creates != 0 || r.starts != 0 {
				t.Fatal("denied work launched", err)
			}
		})
	}
}

func TestDisconnectAfterRemoveRetainsCleanupObligation(t *testing.T) {
	c, r, _, e := setup(t)
	if err := c.execution(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	e = current(t, c)
	cleanup := storetest.Encode(t, "HostCommand", map[string]any{"commandId": "cleanup-a", "kind": "cleanup", "executionId": e.Identity.ExecutionID, "generation": "1"})
	if _, err := c.Store.AcceptCommand(context.Background(), c.Scope, cleanup); err != nil {
		t.Fatal(err)
	}
	c.cancelled[executionKey(e)] = true
	r.disconnectAfterRemove = true
	if err := c.execution(context.Background(), e); err == nil {
		t.Fatal("unverified cleanup succeeded")
	}
	e = current(t, c)
	if e.State != "cleanup-pending" || !e.CleanupPending || r.removes != 1 {
		t.Fatal("cleanup obligation lost")
	}
	if _, err := os.Stat(filepath.Join(c.KeysDirectory, requestID(e)+".key")); err != nil {
		t.Fatal("recovery key discarded before cleanup commit")
	}
}

func TestVerifiedCleanupCommitsAndRemainsInReconciliationHistory(t *testing.T) {
	c, _, _, e := setup(t)
	if err := c.execution(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	e = current(t, c)
	command := storetest.Encode(t, "HostCommand", map[string]any{"commandId": "cleanup-a", "kind": "cleanup", "executionId": e.Identity.ExecutionID, "generation": "1"})
	if _, err := c.Store.AcceptCommand(context.Background(), c.Scope, command); err != nil {
		t.Fatal(err)
	}
	if err := c.execution(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	e = current(t, c)
	if e.State != "cleaned" || e.CleanupPending || e.LastSequence != "4" {
		t.Fatalf("cleanup not atomic: %+v", e)
	}
	if _, err := os.Stat(filepath.Join(c.KeysDirectory, requestID(e)+".key")); !os.IsNotExist(err) {
		t.Fatal("completed attempt retained encryption key")
	}
	if err := c.Store.AckEvents(context.Background(), c.Scope, agent.Watermark{ExecutionID: e.Identity.ExecutionID, Generation: "1", ContiguousSequence: "4"}); err != nil {
		t.Fatal(err)
	}
	rows, err := c.Store.Incomplete(context.Background(), agent.ExecutionCursor{}, 100)
	if err != nil || len(rows) != 0 {
		t.Fatal("completed execution not compacted", err)
	}
	if current(t, c).State != "cleaned" {
		t.Fatal("full reconciliation history lost")
	}
}

func TestNeverStartedProofReleasesOnlyDurablyFencedAttempt(t *testing.T) {
	c, r, _, e := setup(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.SigningKey = key
	var start protocol.StartCommand
	_ = json.Unmarshal(e.Command, &start)
	fence := storetest.Encode(t, "HostCommand", map[string]any{"commandId": "fence-a", "kind": "fence-never-started", "executionId": e.Identity.ExecutionID, "generation": "1", "tenantId": c.Scope.TenantID, "hostId": c.Scope.HostID, "sessionEpoch": c.Scope.SessionEpoch, "endpointIdentity": c.Scope.EndpointIdentity, "startCommandId": e.CommandID, "startPayloadHash": start.PayloadHash, "specHash": e.Identity.SpecHash, "challenge": strings.Repeat("c", 43), "issuedAt": time.Now().UTC().Format(wireTime)})
	if _, err = c.Store.AcceptCommand(context.Background(), c.Scope, fence); err != nil {
		t.Fatal(err)
	}
	if err = c.execution(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	e = current(t, c)
	if e.State != "cleaned" || e.LastSequence != "1" || r.creates != 0 || r.starts != 0 {
		t.Fatal("never-started completion failed")
	}
	if err = c.Store.ClaimCreation(context.Background(), e.Command, c.Authority); err == nil {
		t.Fatal("fenced attempt became launchable")
	}
}

func TestDurableDuplicateReceiptSurvivesControllerDrainAndRemoteDenial(t *testing.T) {
	c, _, remote, e := setup(t)
	c.Drained = func() bool { return true }
	remote.deny = true
	before := c.Store.Health(context.Background())
	r, err := c.accept(context.Background(), e.Command)
	if err != nil || !r.Duplicate {
		t.Fatal("durable receipt was blocked by admission", err)
	}
	after := c.Store.Health(context.Background())
	if before.Revision != after.Revision {
		t.Fatal("receipt replay mutated journal")
	}
	if _, err = c.accept(context.Background(), storetest.Start(t, "new")); err == nil {
		t.Fatal("drained controller admitted new work")
	}
}

func TestMatchingResourceWithoutPermanentCreationClaimIsQuarantined(t *testing.T) {
	c, r, _, e := setup(t)
	r.object = &dockerengine.Object{ID: strings.Repeat("c", 64), State: "running"}
	if err := c.execution(context.Background(), e); err == nil {
		t.Fatal("unclaimed resource adopted")
	}
	if r.starts != 0 || r.stops != 0 || r.removes != 0 {
		t.Fatal("unclaimed resource mutated")
	}
}

func TestExpiredHandoffRemovedWhilePlatformUnavailable(t *testing.T) {
	c, runtime, remote, e := setup(t)
	p, err := c.plan(e)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.handoff(p, []byte("CANARY-JIT"), time.Now().Add(-time.Minute).UTC().Format(wireTime)); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(c.KeysDirectory, requestID(e)+".key")
	if err = os.WriteFile(key, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	remote.deny = true
	runtime.disconnectAfterRemove = true
	runtime.removes = 1
	if err = c.reconcile(context.Background()); err == nil {
		t.Fatal("expected unavailable runtime")
	}
	if _, err = os.Lstat(filepath.Join(c.Profile.BootstrapRoot, p.Name, "bootstrap.json")); !os.IsNotExist(err) {
		t.Fatal("expired bootstrap retained", err)
	}
	if _, err = os.Stat(key); err != nil {
		t.Fatal("recipient key removed before cleanup", err)
	}
	if current(t, c).State != "accepted" || runtime.creates != 0 {
		t.Fatal("expiry mutated execution or launched work")
	}
}
