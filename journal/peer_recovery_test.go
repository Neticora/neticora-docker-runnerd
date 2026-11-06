//go:build linux

package journal

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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
)

func approvalForJournal(t *testing.T, s *SQLiteStore, start []byte, change func(*protocol.PeerRecoveryPlan)) *peerrecovery.Authorization {
	a, _ := approvalForJournalMaterial(t, s, start, change)
	return a
}

func approvalForJournalMaterial(t *testing.T, s *SQLiteStore, start []byte, change func(*protocol.PeerRecoveryPlan)) (*peerrecovery.Authorization, []byte) {
	t.Helper()
	ctx := context.Background()
	h := s.Health(ctx)
	command, err := protocol.DecodeStartCommand(start)
	if err != nil {
		t.Fatal(err)
	}
	executions, err := s.Incomplete(ctx, agent.ExecutionCursor{}, 100)
	if err != nil || len(executions) != 1 {
		t.Fatal("execution", err)
	}
	e := executions[0]
	now := time.Now().UTC()
	format := "2006-01-02T15:04:05.000Z"
	resource := strings.Repeat("d", 64)
	plan := protocol.PeerRecoveryPlan{Domain: "neticora-runnerd-peer-recovery-plan-v1", AgentVersion: "test-version", Challenge: protocol.PeerRecoveryChallenge{ChallengeId: "challenge-a", Nonce: strings.Repeat("n", 43), TenantId: storetest.Scope.TenantID, Identity: protocol.HostIdentity{HostId: storetest.Scope.HostID, KeyId: "key-a", KeyVersion: "1", SessionEpoch: "2"}, ServerSnapshotHash: strings.Repeat("a", 64), ExpiresAt: now.Add(10 * time.Minute).Format(format)}, InstallationId: storetest.Scope.InstallationID, BootId: "current-boot-identity", SourceEndpointIdentity: storetest.Scope.EndpointIdentity, TargetEndpointIdentity: "replacement-peer", JournalId: h.JournalID, JournalRevision: h.Revision, InventoryGeneration: "2", InventoryHash: strings.Repeat("b", 64), ObservedAt: now.Format(format), Executions: []protocol.PeerRecoveryExecutionPlan{{ExecutionId: e.Identity.ExecutionID, Generation: e.Identity.Generation, OriginalSessionEpoch: "1", SpecHash: e.Identity.SpecHash, StartCommandHash: command.PayloadHash, ObservedResourceId: &resource, ObservedState: "prepared", InspectionHash: strings.Repeat("c", 64), LastSequence: e.LastSequence, AckSequence: e.AckSequence, PendingEvents: []protocol.PeerRecoveryEventReference{}, CreationClaim: "verified", NativeState: e.State}}}
	if change != nil {
		change(&plan)
	}
	hash, _ := peerrecovery.Hash(plan)
	approvalID := "approval-a"
	if plan.Challenge.ChallengeId != "challenge-a" {
		approvalID = "approval-" + plan.Challenge.ChallengeId
	}
	manifest := protocol.PeerRecoveryApprovalManifest{Domain: "neticora-runnerd-peer-recovery-approval-v1", ApprovalId: approvalID, AuditReference: "Operator reviewed exact peer transition", Plan: plan, PlanHash: hash, IssuedAt: now.Format(format), ExpiresAt: now.Add(5 * time.Minute).Format(format), Decisions: []protocol.PeerRecoveryDecision{{ExecutionId: plan.Executions[0].ExecutionId, Generation: plan.Executions[0].Generation, Action: "cleanup"}}}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	canonical, _ := peerrecovery.Canonical(manifest)
	reply := protocol.PeerRecoveryAuthorization{Identity: plan.Challenge.Identity, Status: "APPROVED", VerifiedAt: now.Format(format), ServerWatermarks: []protocol.EventAck{{ExecutionId: plan.Executions[0].ExecutionId, Generation: plan.Executions[0].Generation, ContiguousSequence: e.AckSequence}}, Approval: protocol.SignedPeerRecoveryApproval{Manifest: manifest, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, canonical))}}
	raw, _ := json.Marshal(reply)
	a, err := peerrecovery.VerifyCommitted(raw, public, plan, now)
	if err != nil {
		t.Fatal(err)
	}
	return a, public
}

func claimedRecovery(t *testing.T) (*SQLiteStore, []byte) {
	t.Helper()
	s := recovery(t, privateDir(t), Options{})
	ctx := context.Background()
	storetest.Reconcile(t, s, storetest.Scope, "1")
	start := storetest.Start(t, "a")
	if _, err := s.AcceptCommand(ctx, storetest.Scope, start); err != nil {
		t.Fatal(err)
	}
	if err := s.PutStartIntent(ctx, storetest.Scope, storetest.Intent(t, start)); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimCreation(ctx, start, Authority{TenantID: "tenant-a", HostID: "host-a", SessionEpoch: "1", EndpointIdentity: "engine-a", KeyID: "key-a"}); err != nil {
		t.Fatal(err)
	}
	return s, start
}

func TestPeerRecoveryPreservesOriginsAndBlocksAdmissionAcrossRestart(t *testing.T) {
	s, start := claimedRecovery(t)
	ctx := context.Background()
	a := approvalForJournal(t, s, start, nil)
	var before []byte
	if err := s.db.QueryRow("SELECT command FROM executions").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyPeerRecovery(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyPeerRecovery(ctx, a); err != nil {
		t.Fatal("repeat approval", err)
	}
	if h := s.Health(ctx); h.Ready || h.Reason != "operator-recovery" {
		t.Fatal("admission enabled", h)
	}
	var after []byte
	var endpoint, epoch string
	var released bool
	if err := s.db.QueryRow("SELECT command,endpoint_identity,session_epoch FROM executions").Scan(&after, &endpoint, &epoch); err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) || endpoint != "engine-a" || epoch != "1" {
		t.Fatal("origin authority rewritten")
	}
	if err := s.db.QueryRow("SELECT released FROM reservations").Scan(&released); err != nil || released {
		t.Fatal("reservation released", err)
	}
	if err := s.CheckPeerRecoveryMutation(ctx, a, "exec-a", "1"); !errors.Is(err, agent.ErrRecoveryRequired) {
		t.Fatal("cleanup intent not required", err)
	}
	if _, err := s.AcceptCommand(ctx, s.scope, storetest.Start(t, "new")); !errors.Is(err, agent.ErrRecoveryRequired) {
		t.Fatal("new work admitted", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRecovery(ctx, s.dir, testOptions(Options{}))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if h := reopened.Health(ctx); h.Ready || h.Reason != "operator-recovery" {
		t.Fatal("restart cleared approval fence", h)
	}
	value, err := reopened.CurrentPeerRecovery(ctx)
	if err != nil || value.Manifest.ApprovalId != "approval-a" {
		t.Fatal("lost durable approval", err)
	}
}

func TestPeerRecoveryRejectsStaleSnapshotsAndChangedNativeFacts(t *testing.T) {
	for _, kind := range []string{"revision", "missing-claim", "changed-hash", "changed-generation", "changed-state", "omitted-execution"} {
		t.Run(kind, func(t *testing.T) {
			s, start := claimedRecovery(t)
			a := approvalForJournal(t, s, start, func(p *protocol.PeerRecoveryPlan) {
				switch kind {
				case "revision":
					p.JournalRevision = "0"
				case "changed-hash":
					p.Executions[0].StartCommandHash = strings.Repeat("e", 64)
				case "changed-generation":
					p.Executions[0].Generation = "2"
				case "changed-state":
					p.Executions[0].NativeState = "running"
				}
			})
			if kind == "missing-claim" {
				files, err := os.ReadDir(s.dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, f := range files {
					if strings.HasSuffix(f.Name(), ".creation.json") {
						if err = s.fences.root.Remove(f.Name()); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if kind == "omitted-execution" {
				if _, err := s.db.Exec("UPDATE executions SET state='cleaned'"); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.ApplyPeerRecovery(context.Background(), a); !errors.Is(err, agent.ErrRecoveryRequired) {
				t.Fatal("inconsistent journal accepted", err)
			}
			if count(t, s, "peer_recovery_approvals") != 0 {
				t.Fatal("rejected approval committed")
			}
		})
	}
}

func TestPeerRecoveryAbruptCommitRetainsReservationsAndDurableFence(t *testing.T) {
	for _, stage := range []string{"before-commit", "after-commit", "after-anchor"} {
		t.Run(stage, func(t *testing.T) {
			s, start := claimedRecovery(t)
			ctx := context.Background()
			a, public := approvalForJournalMaterial(t, s, start, nil)
			value, err := a.Approval().Value()
			if err != nil {
				t.Fatal(err)
			}
			reply := protocol.PeerRecoveryAuthorization{Approval: value, Identity: value.Manifest.Plan.Challenge.Identity, Status: "APPROVED", VerifiedAt: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), ServerWatermarks: a.Watermarks()}
			bundle := struct {
				Reply  protocol.PeerRecoveryAuthorization `json:"reply"`
				Public string                             `json:"public"`
			}{reply, string(public)}
			raw, err := json.Marshal(bundle)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.dir, "peer-recovery-fixture.json")
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestPeerRecoveryCrashChild$", "-test.count=1")
			command.Env = append(os.Environ(), "RUNNERD_PEER_CRASH_DIR="+s.dir, "RUNNERD_PEER_CRASH_STAGE="+stage)
			err = command.Run()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 73 {
				t.Fatal("crash barrier not reached", err)
			}
			reopened, err := OpenRecovery(ctx, s.dir, testOptions(Options{}))
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			var released bool
			if err = reopened.db.QueryRow("SELECT released FROM reservations").Scan(&released); err != nil || released {
				t.Fatal("crash released reservation", err)
			}
			expected := 1
			if stage == "before-commit" {
				expected = 0
			}
			if count(t, reopened, "peer_recovery_approvals") != expected {
				t.Fatal("unexpected committed approval")
			}
			if reopened.Health(ctx).Ready {
				t.Fatal("crash restored admission")
			}
			if err = reopened.ApplyPeerRecovery(ctx, a); err != nil {
				t.Fatal("crash prevented exact safe approval retry", err)
			}
			if h := reopened.Health(ctx); h.Ready || h.Reason != "operator-recovery" {
				t.Fatal("retry cleared durable fence", h)
			}
		})
	}
}

func TestPeerRecoveryCrashChild(t *testing.T) {
	dir := os.Getenv("RUNNERD_PEER_CRASH_DIR")
	if dir == "" {
		t.Skip("subprocess only")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "peer-recovery-fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Reply  protocol.PeerRecoveryAuthorization `json:"reply"`
		Public string                             `json:"public"`
	}
	if json.Unmarshal(raw, &bundle) != nil {
		t.Fatal("bundle")
	}
	reply, _ := json.Marshal(bundle.Reply)
	a, err := peerrecovery.VerifyCommitted(reply, []byte(bundle.Public), bundle.Reply.Approval.Manifest.Plan, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenRecovery(context.Background(), dir, testOptions(Options{}))
	if err != nil {
		t.Fatal(err)
	}
	s.fault = func(stage string) error {
		if stage == os.Getenv("RUNNERD_PEER_CRASH_STAGE") {
			os.Exit(73)
		}
		return nil
	}
	if err = s.ApplyPeerRecovery(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash barrier missed")
}

func TestPeerRecoveryRenewalSupersedesAuthorityWithoutCompletingWork(t *testing.T) {
	s, start := claimedRecovery(t)
	ctx := context.Background()
	first := approvalForJournal(t, s, start, nil)
	if err := s.ApplyPeerRecovery(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := approvalForJournal(t, s, start, func(p *protocol.PeerRecoveryPlan) {
		p.Challenge.ChallengeId = "challenge-b"
		p.Challenge.Nonce = strings.Repeat("m", 43)
	})
	if err := s.ApplyPeerRecovery(ctx, second); err != nil {
		t.Fatal("renewal refused", err)
	}
	var completed, superseded bool
	if err := s.db.QueryRow("SELECT completed,superseded FROM peer_recovery_approvals WHERE approval_id='approval-a'").Scan(&completed, &superseded); err != nil {
		t.Fatal(err)
	}
	if completed || !superseded {
		t.Fatal("unfinished approval reported completed")
	}
	if err := s.ApplyPeerRecovery(ctx, first); !errors.Is(err, agent.ErrConflict) {
		t.Fatal("superseded authority revived", err)
	}
	var released bool
	if err := s.db.QueryRow("SELECT released FROM reservations").Scan(&released); err != nil || released {
		t.Fatal("renewal lost reservation", err)
	}
	if h := s.Health(ctx); h.Ready || h.Reason != "operator-recovery" {
		t.Fatal("renewal enabled admission", h)
	}
}

func TestPeerRecoveryRefusesCorruptSeparateCommandMetadata(t *testing.T) {
	s, start := claimedRecovery(t)
	ctx := context.Background()
	a := approvalForJournal(t, s, start, nil)
	if _, err := s.db.Exec("UPDATE commands SET payload_hash=?", strings.Repeat("f", 64)); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyPeerRecovery(ctx, a); !errors.Is(err, agent.ErrStoreUnavailable) {
		t.Fatal("inconsistent stored command accepted", err)
	}
	if count(t, s, "peer_recovery_approvals") != 0 || s.Health(ctx).Ready {
		t.Fatal("corruption acquired authority")
	}
}
