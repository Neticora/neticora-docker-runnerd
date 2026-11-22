package connectionrecovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

type runtimeFixture struct {
	endpoint string
	ids      []string
}

func (r *runtimeFixture) Probe(context.Context) (string, error)       { return r.endpoint, nil }
func (r *runtimeFixture) Inventory(context.Context) ([]string, error) { return r.ids, nil }

type platformFixture struct {
	mu                     sync.Mutex
	approved, outage, lose bool
	public                 ed25519.PublicKey
	receipts               map[string]protocol.ConnectionResyncResponse
	calls, commits         int
	operations             map[string]bool
}

func (p *platformFixture) Post(ctx context.Context, path, token string, message protocol.Outbound, schema string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if path != "/connection-resync" || token != "" || schema != "ConnectionResyncResponse" {
		return nil, ErrBlocked
	}
	if p.outage {
		return nil, errors.New("offline")
	}
	var signed protocol.SignedConnectionResyncRequest
	if json.Unmarshal(message.Bytes(), &signed) != nil {
		return nil, ErrBlocked
	}
	raw, _ := peerrecovery.Canonical(signed.Proof)
	sig, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	if !ed25519.Verify(p.public, raw, sig) {
		return nil, ErrBlocked
	}
	r := signed.Proof.Request
	p.operations[r.OperationId] = true
	if receipt, ok := p.receipts[r.OperationId]; ok {
		return json.Marshal(receipt)
	}
	h, _ := peerrecovery.Hash(r)
	receipt := protocol.ConnectionResyncResponse{OperationId: r.OperationId, RequestHash: h, State: "pending-approval", Reason: "administrator-approval-required", Identity: r.Identity, TenantId: r.TenantId, InstallationId: r.InstallationId, RunnerDeploymentId: r.RunnerDeploymentId, BootId: r.TargetBootId, EndpointIdentity: r.TargetEndpointIdentity}
	if p.approved {
		receipt.State = "committed"
		receipt.Reason = "observation-only-binding-committed"
		receipt.Identity.SessionEpoch = "2"
		p.receipts[r.OperationId] = receipt
		p.commits++
		if p.lose {
			p.lose = false
			return nil, errors.New("lost committed response")
		}
	}
	return json.Marshal(receipt)
}
func setup(t *testing.T) (*Manager, execution.Credentials, *platformFixture) {
	t.Helper()
	path := t.TempDir()
	os.Chmod(path, 0700)
	state := filepath.Join(path, "state")
	os.Mkdir(state, 0700)
	s, err := journal.OpenRecovery(context.Background(), state, journal.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credentials := execution.Credentials{InstallationID: "install-a", TenantID: "tenant-a", Identity: protocol.HostIdentity{HostId: "host-a", KeyId: "key-a", KeyVersion: "1", SessionEpoch: "1"}, BootID: "old_boot_0123456789", EndpointIdentity: "engine-a"}
	remote := &platformFixture{public: pub, receipts: map[string]protocol.ConnectionResyncResponse{}, operations: map[string]bool{}}
	c := config.Config{StateDir: state, Connection: &config.Connection{TenantID: "tenant-a", RunnerDeploymentID: "pool-a", EnrollmentRequestID: "enroll-a", PublicKeyFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	return &Manager{Store: s, Runtime: &runtimeFixture{endpoint: "engine-b"}, Remote: remote, Config: c, Key: key, Boot: "new_boot_0123456789"}, credentials, remote
}
func reopen(t *testing.T, m *Manager) {
	t.Helper()
	m.Store.Close()
	s, err := journal.OpenRecovery(context.Background(), m.Config.StateDir, journal.Options{})
	if err != nil {
		t.Fatal(err)
	}
	m.Store = s
	t.Cleanup(func() { s.Close() })
}
func TestApprovalAndLostResponseRecoverOnlyOriginalOperation(t *testing.T) {
	m, original, remote := setup(t)
	ctx := context.Background()
	_, id, reason, err := m.Step(ctx, original)
	if err == nil || reason != "administrator-approval-required" {
		t.Fatal(reason, err)
	}
	pending, e := m.Store.ConnectionRecovery(ctx)
	if e != nil || pending == nil || pending.Intent.OperationId != id || pending.Receipt != nil {
		t.Fatal("intent not durable", e)
	}
	remote.approved = true
	remote.lose = true
	if _, next, _, err := m.Step(ctx, original); err == nil || next != id {
		t.Fatal("ambiguous response not retained", err)
	}
	reopen(t, m)
	current, next, _, err := m.Step(ctx, original)
	if err != nil || next != id || current.Identity.SessionEpoch != "2" || current.Identity.HostId != original.Identity.HostId || current.BootID != m.Boot {
		t.Fatal(current, err)
	}
	if remote.commits != 1 || len(remote.operations) != 1 || m.Store.Health(ctx).Ready {
		t.Fatal("replay/qualification violation")
	}
	before := remote.calls
	if _, _, _, err = m.Step(ctx, original); err != nil || remote.calls != before {
		t.Fatal("settled transition called platform again", err)
	}
}
func TestLocalPersistenceInterruptionsRetainExactTransition(t *testing.T) {
	for _, boundary := range []string{"before-request", "after-platform-acceptance", "before-binding-rename", "after-binding-sync"} {
		t.Run(boundary, func(t *testing.T) {
			m, original, remote := setup(t)
			remote.approved = true
			injected := false
			m.Checkpoint = func(at string) error {
				if at == boundary && !injected {
					injected = true
					return errors.New("interrupted")
				}
				return nil
			}
			_, id, _, err := m.Step(context.Background(), original)
			if err == nil || !injected {
				t.Fatal("fault not reached", err)
			}
			reopen(t, m)
			m.Checkpoint = nil
			current, next, _, err := m.Step(context.Background(), original)
			if err != nil || next != id || current.Identity.SessionEpoch != "2" {
				t.Fatal(current, err)
			}
			if remote.commits != 1 || len(remote.operations) != 1 || m.Store.Health(context.Background()).Ready {
				t.Fatal("retry replaced authority")
			}
		})
	}
}
func TestUnknownResourceAndOutageDoNotChangeBinding(t *testing.T) {
	m, original, remote := setup(t)
	m.Runtime.(*runtimeFixture).ids = []string{"unowned-original-label"}
	if _, _, reason, err := m.Step(context.Background(), original); err == nil || reason != "unknown-runtime-resources" || remote.calls != 0 {
		t.Fatal("unknown resources bypassed")
	}
	m.Runtime.(*runtimeFixture).ids = nil
	remote.outage = true
	_, id, _, err := m.Step(context.Background(), original)
	if err == nil || id == "" {
		t.Fatal("outage lost intent")
	}
	reopen(t, m)
	_, next, _, err := m.Step(context.Background(), original)
	if err == nil || next != id {
		t.Fatal("outage replaced intent")
	}
	effective, err := Load(m.Config, original)
	if err != nil || effective != original {
		t.Fatal("outage rebound credentials", err)
	}
	m.Boot = "another_boot_012345"
	remote.outage = false
	if _, next, reason, err := m.Step(context.Background(), original); err == nil || next != id || reason != "pending-target-changed" {
		t.Fatal("ambiguous transition replaced")
	}
}
func TestConcurrentRecoveryKeepsOneDurableOperation(t *testing.T) {
	m, original, remote := setup(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _, _, _ = m.Step(context.Background(), original) }()
	}
	wg.Wait()
	record, err := m.Store.ConnectionRecovery(context.Background())
	if err != nil || record == nil || len(remote.operations) != 1 {
		t.Fatal("concurrent operations conflicted", err)
	}
}

func TestVerifiedRebootAcceptsImmediateAutomaticCommit(t *testing.T) {
	m, original, remote := setup(t)
	remote.approved = true
	current, id, reason, err := m.Step(context.Background(), original)
	if err != nil || reason != "committed" || id == "" || current.Identity.SessionEpoch != "2" {
		t.Fatal("automatic result did not resume", reason, err)
	}
	if remote.calls != 1 || remote.commits != 1 || m.Store.Health(context.Background()).Ready {
		t.Fatal("automatic observation changed execution authority")
	}
}
