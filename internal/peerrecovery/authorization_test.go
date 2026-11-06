package peerrecovery

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

func TestCommittedAuthorizationRejectsFencingAndStaleSnapshots(t *testing.T) {
	p := testPlan(t)
	pub, key := testKey(t)
	signed, err := protocol.DecodeSignedPeerRecoveryApproval(encodedApproval(t, testApproval(t, p), key))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*protocol.PeerRecoveryAuthorization){
		"current":   func(a *protocol.PeerRecoveryAuthorization) {},
		"revoked":   func(a *protocol.PeerRecoveryAuthorization) { a.Status = "REVOKED" },
		"hold":      func(a *protocol.PeerRecoveryAuthorization) { a.Status = "HOLD" },
		"completed": func(a *protocol.PeerRecoveryAuthorization) { a.Status = "COMPLETED" },
		"epoch":     func(a *protocol.PeerRecoveryAuthorization) { a.Identity.SessionEpoch = "5" },
		"key":       func(a *protocol.PeerRecoveryAuthorization) { a.Identity.KeyId = "other" },
		"stale-reply": func(a *protocol.PeerRecoveryAuthorization) {
			a.VerifiedAt = testNow.Add(-11 * time.Second).Format("2006-01-02T15:04:05.000Z")
		},
		"future-reply": func(a *protocol.PeerRecoveryAuthorization) {
			a.VerifiedAt = testNow.Add(time.Minute).Format("2006-01-02T15:04:05.000Z")
		},
		"lost-native-tail":  func(a *protocol.PeerRecoveryAuthorization) { a.ServerWatermarks[0].ContiguousSequence = "4" },
		"ack-regressed":     func(a *protocol.PeerRecoveryAuthorization) { a.ServerWatermarks[0].ContiguousSequence = "2" },
		"missing-execution": func(a *protocol.PeerRecoveryAuthorization) { a.ServerWatermarks = nil },
		"duplicate-execution": func(a *protocol.PeerRecoveryAuthorization) {
			a.ServerWatermarks = append(a.ServerWatermarks, a.ServerWatermarks[0])
		},
		"wrong-generation": func(a *protocol.PeerRecoveryAuthorization) { a.ServerWatermarks[0].Generation = "2" },
	} {
		t.Run(name, func(t *testing.T) {
			reply := protocol.PeerRecoveryAuthorization{Approval: signed, Identity: p.Challenge.Identity, Status: "APPROVED", VerifiedAt: testNow.Format("2006-01-02T15:04:05.000Z"), ServerWatermarks: []protocol.EventAck{{ExecutionId: p.Executions[0].ExecutionId, Generation: p.Executions[0].Generation, ContiguousSequence: "3"}}}
			change(&reply)
			raw, _ := json.Marshal(reply)
			if name == "current" {
				if err := protocol.Validate("PeerRecoveryAuthorization", raw); err != nil {
					t.Fatal(err)
				}
			}
			a, err := VerifyCommitted(raw, pub, p, testNow)
			if name != "current" {
				if !errors.Is(err, ErrApproval) {
					t.Fatal("invalid platform authority accepted")
				}
				return
			}
			if err != nil || !a.Current(testNow) || a.Current(testNow.Add(11*time.Second)) {
				t.Fatal("authorization freshness failed", err)
			}
			w := a.Watermarks()
			w[0].ContiguousSequence = "100"
			if a.Watermarks()[0].ContiguousSequence != "3" {
				t.Fatal("mutable authority")
			}
		})
	}
}

func TestContinuingAuthorityRequiresActualNativeSuffixAndFinalAck(t *testing.T) {
	p := testPlan(t)
	pub, key := testKey(t)
	signed, err := protocol.DecodeSignedPeerRecoveryApproval(encodedApproval(t, testApproval(t, p), key))
	if err != nil {
		t.Fatal(err)
	}
	reply := protocol.PeerRecoveryAuthorization{Approval: signed, Identity: p.Challenge.Identity, Status: "APPLIED", VerifiedAt: testNow.Format("2006-01-02T15:04:05.000Z"), ServerWatermarks: []protocol.EventAck{{ExecutionId: p.Executions[0].ExecutionId, Generation: "1", ContiguousSequence: "4"}}}
	raw, _ := json.Marshal(reply)
	if _, err := VerifyCommitted(raw, pub, p, testNow); !errors.Is(err, ErrApproval) {
		t.Fatal("stale initial journal accepted")
	}
	native := []NativeProgress{{ExecutionID: p.Executions[0].ExecutionId, Generation: "1", LastSequence: "4", AckSequence: "3"}}
	if _, err := VerifyContinuing(raw, pub, p, native, testNow); err != nil {
		t.Fatal("durable suffix rejected", err)
	}
	native[0].LastSequence = "3"
	if _, err := VerifyContinuing(raw, pub, p, native, testNow); !errors.Is(err, ErrApproval) {
		t.Fatal("invented native suffix accepted")
	}
	native[0].LastSequence = "4"
	reply.Status = "COMPLETED"
	raw, _ = json.Marshal(reply)
	if _, err := VerifyContinuing(raw, pub, p, native, testNow); !errors.Is(err, ErrApproval) {
		t.Fatal("completion granted mutation authority")
	}
	if _, err := VerifyCompletion(raw, pub, p, native, testNow); !errors.Is(err, ErrApproval) {
		t.Fatal("uncommitted final native ACK accepted")
	}
	native[0].AckSequence = "4"
	if c, err := VerifyCompletion(raw, pub, p, native, testNow); err != nil || !c.Current(testNow) {
		t.Fatal("final receipt rejected", err)
	}
}

func TestExpiredApprovalIsHistoricalCompletionEvidenceOnly(t *testing.T) {
	p := testPlan(t)
	pub, key := testKey(t)
	signed, err := protocol.DecodeSignedPeerRecoveryApproval(encodedApproval(t, testApproval(t, p), key))
	if err != nil {
		t.Fatal(err)
	}
	native := []NativeProgress{{ExecutionID: p.Executions[0].ExecutionId, Generation: "1", LastSequence: "4", AckSequence: "4"}}
	afterExpiry := testNow.Add(10*time.Minute + time.Second)
	reply := protocol.PeerRecoveryAuthorization{Approval: signed, Identity: p.Challenge.Identity, Status: "COMPLETED", VerifiedAt: afterExpiry.Format("2006-01-02T15:04:05.000Z"), ServerWatermarks: []protocol.EventAck{{ExecutionId: p.Executions[0].ExecutionId, Generation: "1", ContiguousSequence: "4"}}}
	raw, _ := json.Marshal(reply)
	completion, err := VerifyCompletion(raw, pub, p, native, afterExpiry)
	if err != nil || !completion.Current(afterExpiry) {
		t.Fatal("fresh completion rejected expired recorded approval", err)
	}
	if completion.RecordedApproval() == nil || completion.ApprovalHash() == "" {
		t.Fatal("completion lost immutable approval evidence")
	}
	reply.Status = "APPLIED"
	raw, _ = json.Marshal(reply)
	if _, err = VerifyContinuing(raw, pub, p, native, afterExpiry); !errors.Is(err, ErrApproval) {
		t.Fatal("expired approval regained mutation authority", err)
	}
	if _, err = VerifyApproval(encodedApproval(t, testApproval(t, p), key), pub, p, afterExpiry); !errors.Is(err, ErrApproval) {
		t.Fatal("expired signature accepted as a fresh approval", err)
	}
	if _, err = VerifyRecordedApproval(encodedApproval(t, testApproval(t, p), key), pub, p, afterExpiry); err != nil {
		t.Fatal("valid recorded signature rejected as historical evidence", err)
	}
}

func TestCompletionRequiresExactFreshServerWatermarks(t *testing.T) {
	p := testPlan(t)
	pub, key := testKey(t)
	signed, err := protocol.DecodeSignedPeerRecoveryApproval(encodedApproval(t, testApproval(t, p), key))
	if err != nil {
		t.Fatal(err)
	}
	native := []NativeProgress{{ExecutionID: p.Executions[0].ExecutionId, Generation: "1", LastSequence: "4", AckSequence: "4"}}
	for name, change := range map[string]func(*protocol.PeerRecoveryAuthorization){
		"stale-reply": func(a *protocol.PeerRecoveryAuthorization) {
			a.VerifiedAt = testNow.Add(-11 * time.Second).Format("2006-01-02T15:04:05.000Z")
		},
		"missing": func(a *protocol.PeerRecoveryAuthorization) { a.ServerWatermarks = nil },
		"behind":  func(a *protocol.PeerRecoveryAuthorization) { a.ServerWatermarks[0].ContiguousSequence = "3" },
		"ahead":   func(a *protocol.PeerRecoveryAuthorization) { a.ServerWatermarks[0].ContiguousSequence = "5" },
	} {
		t.Run(name, func(t *testing.T) {
			reply := protocol.PeerRecoveryAuthorization{Approval: signed, Identity: p.Challenge.Identity, Status: "COMPLETED", VerifiedAt: testNow.Format("2006-01-02T15:04:05.000Z"), ServerWatermarks: []protocol.EventAck{{ExecutionId: p.Executions[0].ExecutionId, Generation: "1", ContiguousSequence: "4"}}}
			change(&reply)
			raw, _ := json.Marshal(reply)
			if _, err := VerifyCompletion(raw, pub, p, native, testNow); !errors.Is(err, ErrApproval) {
				t.Fatal("inexact completion accepted", err)
			}
		})
	}
}
