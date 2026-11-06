package peerrecovery

import (
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
)

func testPlan(t *testing.T) protocol.PeerRecoveryPlan {
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
		t.Fatal("invalid fixtures")
	}
	for _, f := range fixtures {
		if f.ID == "peer-recovery-PeerRecoveryPlan" {
			p, e := protocol.DecodePeerRecoveryPlan(f.Value)
			if e != nil {
				t.Fatal(e)
			}
			return p
		}
	}
	t.Fatal("missing recovery fixture")
	return protocol.PeerRecoveryPlan{}
}

func testKey(t *testing.T) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), key
}
func sign(t *testing.T, value any, key ed25519.PrivateKey) string {
	t.Helper()
	raw, err := Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))
}
func testApproval(t *testing.T, p protocol.PeerRecoveryPlan) protocol.PeerRecoveryApprovalManifest {
	t.Helper()
	hash, err := Hash(p)
	if err != nil {
		t.Fatal(err)
	}
	d := []protocol.PeerRecoveryDecision{}
	for _, e := range p.Executions {
		d = append(d, protocol.PeerRecoveryDecision{ExecutionId: e.ExecutionId, Generation: e.Generation, Action: "observe-and-cleanup"})
	}
	return protocol.PeerRecoveryApprovalManifest{Domain: "neticora-runnerd-peer-recovery-approval-v1", ApprovalId: "approval-a", AuditReference: "Explicit independent operator review", Plan: p, PlanHash: hash, Decisions: d, IssuedAt: "2026-11-05T12:00:00.000Z", ExpiresAt: "2026-11-05T12:10:00.000Z"}
}
func encodedApproval(t *testing.T, m protocol.PeerRecoveryApprovalManifest, key ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := json.Marshal(protocol.SignedPeerRecoveryApproval{Manifest: m, Signature: sign(t, m, key)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var testNow = time.Date(2026, 11, 5, 12, 1, 0, 0, time.UTC)

func TestApprovalBindsExactPlanAndIndependentKey(t *testing.T) {
	p := testPlan(t)
	pub, key := testKey(t)
	m := testApproval(t, p)
	raw := encodedApproval(t, m, key)
	a, err := VerifyApproval(raw, pub, p, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash() == "" {
		t.Fatal("missing approval identity")
	}
	value, err := a.Value()
	if err != nil {
		t.Fatal(err)
	}
	value.Manifest.Plan.TargetEndpointIdentity = "mutated"
	again, _ := a.Value()
	if again.Manifest.Plan.TargetEndpointIdentity != "peer-new" {
		t.Fatal("approval snapshot aliases caller data")
	}
	wrong, _ := testKey(t)
	if _, err := VerifyApproval(raw, wrong, p, testNow); !errors.Is(err, ErrApproval) {
		t.Fatal("different authority accepted")
	}
	for name, change := range map[string]func(*protocol.PeerRecoveryPlan){
		"version":   func(p *protocol.PeerRecoveryPlan) { p.AgentVersion = "other-build" },
		"host":      func(p *protocol.PeerRecoveryPlan) { p.Challenge.Identity.HostId = "other" },
		"tenant":    func(p *protocol.PeerRecoveryPlan) { p.Challenge.TenantId = "other" },
		"session":   func(p *protocol.PeerRecoveryPlan) { p.Challenge.Identity.SessionEpoch = "5" },
		"key":       func(p *protocol.PeerRecoveryPlan) { p.Challenge.Identity.KeyId = "other" },
		"peer":      func(p *protocol.PeerRecoveryPlan) { p.TargetEndpointIdentity = "other" },
		"origin":    func(p *protocol.PeerRecoveryPlan) { p.SourceEndpointIdentity = "other" },
		"journal":   func(p *protocol.PeerRecoveryPlan) { p.JournalId = strings.Repeat("b", 64) },
		"revision":  func(p *protocol.PeerRecoveryPlan) { p.JournalRevision = "21" },
		"challenge": func(p *protocol.PeerRecoveryPlan) { p.Challenge.Nonce = strings.Repeat("z", 43) },
		"scope":     func(p *protocol.PeerRecoveryPlan) { p.Executions[0].Generation = "2" },
	} {
		t.Run(name, func(t *testing.T) {
			expected := testPlan(t)
			change(&expected)
			if _, err := VerifyApproval(raw, pub, expected, testNow); !errors.Is(err, ErrApproval) {
				t.Fatal("changed recovery scope accepted")
			}
		})
	}
}

func TestApprovalRejectsStaleUnscopedAndUnsafeDecisions(t *testing.T) {
	pub, key := testKey(t)
	for name, change := range map[string]func(*protocol.PeerRecoveryApprovalManifest){
		"expired":              func(m *protocol.PeerRecoveryApprovalManifest) { m.ExpiresAt = "2026-11-05T12:00:01.000Z" },
		"future":               func(m *protocol.PeerRecoveryApprovalManifest) { m.IssuedAt = "2026-11-05T12:05:00.000Z" },
		"wrong-hash":           func(m *protocol.PeerRecoveryApprovalManifest) { m.PlanHash = strings.Repeat("b", 64) },
		"missing-decision":     func(m *protocol.PeerRecoveryApprovalManifest) { m.Decisions = []protocol.PeerRecoveryDecision{} },
		"extra-decision":       func(m *protocol.PeerRecoveryApprovalManifest) { m.Decisions = append(m.Decisions, m.Decisions[0]) },
		"different-generation": func(m *protocol.PeerRecoveryApprovalManifest) { m.Decisions[0].Generation = "2" },
		"start":                func(m *protocol.PeerRecoveryApprovalManifest) { m.Decisions[0].Action = "start" },
		"no-creation-fence": func(m *protocol.PeerRecoveryApprovalManifest) {
			m.Plan.Executions[0].CreationClaim = "not-claimed"
			m.PlanHash, _ = Hash(m.Plan)
		},
		"missing-container": func(m *protocol.PeerRecoveryApprovalManifest) {
			m.Plan.Executions[0].ObservedState = "absent"
			m.Plan.Executions[0].ObservedResourceId = nil
			m.PlanHash, _ = Hash(m.Plan)
		},
		"uncertain": func(m *protocol.PeerRecoveryApprovalManifest) {
			m.Plan.Executions[0].ObservedState = "unknown"
			m.PlanHash, _ = Hash(m.Plan)
		},
		"unsigned-absence": func(m *protocol.PeerRecoveryApprovalManifest) { m.Decisions[0].Action = "verify-absent" },
	} {
		t.Run(name, func(t *testing.T) {
			p := testPlan(t)
			m := testApproval(t, p)
			change(&m)
			if _, err := VerifyApproval(encodedApproval(t, m, key), pub, m.Plan, testNow); !errors.Is(err, ErrApproval) {
				t.Fatal("unsafe approval accepted")
			}
		})
	}
}

func TestMissingAndAmbiguousResourcesMayOnlyHoldWithoutWitness(t *testing.T) {
	pub, key := testKey(t)
	for _, state := range []protocol.PeerRecoveryExecutionPlanObservedState{"absent", "unknown"} {
		p := testPlan(t)
		p.Executions[0].ObservedState = state
		p.Executions[0].ObservedResourceId = nil
		p.Executions[0].CreationClaim = "ambiguous"
		m := testApproval(t, p)
		m.Decisions[0].Action = "hold"
		if _, err := VerifyApproval(encodedApproval(t, m, key), pub, p, testNow); err != nil {
			t.Fatal("cannot retain ambiguous ownership", err)
		}
	}
}

func TestHostProposalRequiresCurrentChallengeAndHostSignature(t *testing.T) {
	p := testPlan(t)
	pub, key := testKey(t)
	raw, _ := json.Marshal(protocol.SignedPeerRecoveryPlan{Plan: p, Signature: sign(t, p, key)})
	if _, err := VerifyPlan(raw, pub, p.Challenge, testNow); err != nil {
		t.Fatal(err)
	}
	challenge := p.Challenge
	challenge.Identity.SessionEpoch = "5"
	if _, err := VerifyPlan(raw, pub, challenge, testNow); !errors.Is(err, ErrApproval) {
		t.Fatal("old epoch proof accepted")
	}
	if _, err := VerifyPlan(raw, pub, p.Challenge, testNow.Add(time.Hour)); !errors.Is(err, ErrApproval) {
		t.Fatal("expired challenge accepted")
	}
	other, _ := testKey(t)
	if _, err := VerifyPlan(raw, other, p.Challenge, testNow); !errors.Is(err, ErrApproval) {
		t.Fatal("unregistered host signature accepted")
	}
}

func TestPlanPreservesPendingFactSequenceAndOriginalIdentity(t *testing.T) {
	for name, change := range map[string]func(*protocol.PeerRecoveryPlan){
		"same-peer":           func(p *protocol.PeerRecoveryPlan) { p.TargetEndpointIdentity = p.SourceEndpointIdentity },
		"future-origin":       func(p *protocol.PeerRecoveryPlan) { p.Executions[0].OriginalSessionEpoch = "5" },
		"lost-event":          func(p *protocol.PeerRecoveryPlan) { p.Executions[0].LastSequence = "4" },
		"ack-ahead":           func(p *protocol.PeerRecoveryPlan) { p.Executions[0].AckSequence = "4" },
		"duplicate-execution": func(p *protocol.PeerRecoveryPlan) { p.Executions = append(p.Executions, p.Executions[0]) },
		"unknown-resource": func(p *protocol.PeerRecoveryPlan) {
			p.Executions[0].OriginalRuntimeRef = &protocol.RuntimeRef{Engine: "docker", Scope: p.SourceEndpointIdentity, ExecutionId: "other", Generation: "1", SpecHash: strings.Repeat("b", 64), ResourceKind: "container", ResourceId: strings.Repeat("d", 64)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := testPlan(t)
			change(&p)
			if !errors.Is(ValidatePlan(p), ErrApproval) {
				t.Fatal("inconsistent journal plan accepted")
			}
		})
	}
}

func TestApprovalRejectsStaleObservationEvenWhenOperatorSignsAgain(t *testing.T) {
	pub, key := testKey(t)
	for _, observed := range []string{"2026-11-05T11:00:00.000Z", "2026-11-05T12:05:00.000Z"} {
		p := testPlan(t)
		p.ObservedAt = observed
		if _, err := VerifyApproval(encodedApproval(t, testApproval(t, p), key), pub, p, testNow); !errors.Is(err, ErrApproval) {
			t.Fatal("stale/future inspection accepted")
		}
	}
}
