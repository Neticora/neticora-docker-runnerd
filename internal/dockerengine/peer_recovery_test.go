package dockerengine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
)

func recoveryAuthority(t *testing.T, e *Engine, p Plan, action string) RecoveryAuthority {
	t.Helper()
	raw, err := os.ReadFile("../../api/fixtures/validation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		ID    string          `json:"id"`
		Value json.RawMessage `json:"value"`
	}
	if json.Unmarshal(raw, &fixtures) != nil {
		t.Fatal("fixtures")
	}
	var plan protocol.PeerRecoveryPlan
	for _, f := range fixtures {
		if f.ID == "peer-recovery-PeerRecoveryPlan" {
			plan, err = protocol.DecodePeerRecoveryPlan(f.Value)
		}
	}
	if err != nil || plan.JournalId == "" {
		t.Fatal("plan", err)
	}
	endpoint, err := e.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	plan.TargetEndpointIdentity = endpoint
	plan.SourceEndpointIdentity = "peer-old"
	plan.ObservedAt = now.Format("2006-01-02T15:04:05.000Z")
	plan.Challenge.ExpiresAt = now.Add(10 * time.Minute).Format("2006-01-02T15:04:05.000Z")
	plan.Executions[0].ObservedResourceId = new(strings.Repeat("c", 64))
	plan.Executions[0].SpecHash = p.Config.Labels[LabelPrefix+"spec"]
	plan.Executions[0].ExecutionId = p.Config.Labels[LabelPrefix+"execution"]
	planHash, _ := peerrecovery.Hash(plan)
	manifest := protocol.PeerRecoveryApprovalManifest{Domain: "neticora-runnerd-peer-recovery-approval-v1", ApprovalId: "approval-a", AuditReference: "Explicit operator recovery review", Plan: plan, PlanHash: planHash, Decisions: []protocol.PeerRecoveryDecision{{ExecutionId: plan.Executions[0].ExecutionId, Generation: "1", Action: protocol.PeerRecoveryDecisionAction(action)}}, IssuedAt: now.Format("2006-01-02T15:04:05.000Z"), ExpiresAt: now.Add(5 * time.Minute).Format("2006-01-02T15:04:05.000Z")}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	canonical, _ := peerrecovery.Canonical(manifest)
	reply := protocol.PeerRecoveryAuthorization{Identity: plan.Challenge.Identity, Status: "APPROVED", VerifiedAt: now.Format("2006-01-02T15:04:05.000Z"), ServerWatermarks: []protocol.EventAck{{ExecutionId: plan.Executions[0].ExecutionId, Generation: "1", ContiguousSequence: "3"}}, Approval: protocol.SignedPeerRecoveryApproval{Manifest: manifest, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, canonical))}}
	encoded, _ := json.Marshal(reply)
	return func(context.Context) (*peerrecovery.Authorization, error) {
		return peerrecovery.VerifyCommitted(encoded, publicPEM, plan, time.Now())
	}
}

func recoveryPlan(p Plan) Plan {
	cfg := *p.Config
	cfg.Labels = map[string]string{}
	for k, v := range p.Config.Labels {
		cfg.Labels[k] = v
	}
	for k, v := range map[string]string{"tenant": "tenant-a", "host": "host-a", "execution": "execution-a", "generation": "1", "spec": strings.Repeat("b", 64), "endpoint": "peer-old"} {
		cfg.Labels[LabelPrefix+k] = v
	}
	p.Config = &cfg
	return p
}

func TestReadOnlyPeerRejectsEveryOrdinaryMutation(t *testing.T) {
	e, p, exists, running, creates, _ := fakeEngine(t)
	e.readOnly = true
	// Both absence and a matching discovered resource must remain read-only.
	for _, present := range []bool{false, true} {
		*exists = present
		if _, err := e.Inventory(context.Background()); err != nil {
			t.Fatal(err)
		}
		_, _ = e.Inspect(context.Background(), p.Name, p)
		if err := e.PrepareImage(context.Background(), p); !errors.Is(err, ErrRecoveryApprovalRequired) {
			t.Fatal(err)
		}
		claimed := false
		_, err := e.Ensure(context.Background(), p, func() error { claimed = true; return nil })
		if !errors.Is(err, ErrRecoveryApprovalRequired) || claimed {
			t.Fatal("creation claim allowed")
		}
		_, err = e.Start(context.Background(), p.Name, p, func() error { t.Fatal("start authority consulted"); return nil })
		if !errors.Is(err, ErrRecoveryApprovalRequired) {
			t.Fatal(err)
		}
		if err = e.Stop(context.Background(), p.Name, p); !errors.Is(err, ErrRecoveryApprovalRequired) {
			t.Fatal(err)
		}
		if err = e.Remove(context.Background(), p.Name, p); !errors.Is(err, ErrRecoveryApprovalRequired) {
			t.Fatal(err)
		}
	}
	if *running || *creates != 0 {
		t.Fatal("read-only adapter mutated Docker")
	}
}

func TestRecoveryMutationRequiresExactResourceAndRechecksPeer(t *testing.T) {
	e, p, exists, _, _, daemon := fakeEngine(t)
	e.readOnly = true
	*exists = true
	p = recoveryPlan(p)
	// The fixture's actual labels remain different: ownership inspection rejects
	// before an authority callback, even if an operator approves this claimed ID.
	calls := 0
	if err := e.RecoverRemove(context.Background(), strings.Repeat("c", 64), p, func(context.Context) (*peerrecovery.Authorization, error) { calls++; return nil, nil }); !errors.Is(err, ErrConflict) || calls != 0 {
		t.Fatal("ownership bypass", err)
	}
	// Make desired and actual labels agree. The server holds this Config pointer.
	// A callback cannot rebind the old adapter even with a valid signed grant.
	// Probe binds first, then changing Docker ID inside authorization must fence.
	_, err := e.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	authority := recoveryAuthority(t, e, p, "cleanup")
	*daemon = "replacement-engine"
	if err = e.recoveryCheck(context.Background(), strings.Repeat("c", 64), p, authority); !errors.Is(err, ErrUnavailable) {
		t.Fatal("peer changed under approval", err)
	}
}

func TestRecoveryHoldNeverAuthorizesMutation(t *testing.T) {
	e, p, _, _, _, _ := fakeEngine(t)
	e.readOnly = true
	p = recoveryPlan(p)
	authority := recoveryAuthority(t, e, p, "hold")
	if err := e.recoveryCheck(context.Background(), strings.Repeat("c", 64), p, authority); !errors.Is(err, ErrRecoveryApprovalRequired) {
		t.Fatal("hold authorized mutation", err)
	}
	authority = recoveryAuthority(t, e, p, "cleanup")
	if err := e.recoveryCheck(context.Background(), strings.Repeat("d", 64), p, authority); !errors.Is(err, ErrRecoveryApprovalRequired) {
		t.Fatal("different resource authorized", err)
	}
	if err := e.recoveryCheck(context.Background(), strings.Repeat("c", 64), p, authority); err != nil {
		t.Fatal("exact cleanup scope rejected", err)
	}
	if !e.readOnly {
		t.Fatal("recovery approval enabled normal mutations")
	}
}
