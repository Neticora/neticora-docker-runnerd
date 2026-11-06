package peerrecovery

import (
	"bytes"
	"strconv"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

// Authorization binds independently signed approval to a fresh reply obtained
// through the authenticated host transport. It is not a durable application
// receipt: the journal must commit the same approval before a runtime mutation.
// Neither the wire status nor a signature on its own establishes this value.
type Authorization struct {
	approval   *OperatorApproval
	verifiedAt time.Time
	expiresAt  time.Time
	watermarks []protocol.EventAck
}

// VerifyCommitted must receive the result of POST /me/recovery over the existing
// authenticated host client, not an operator-supplied file. expected is the exact
// frozen local plan. The caller must serialize this with its durable application.
type NativeProgress struct{ ExecutionID, Generation, LastSequence, AckSequence string }

func VerifyCommitted(raw, operatorPublicPEM []byte, expected protocol.PeerRecoveryPlan, now time.Time) (*Authorization, error) {
	progress := make([]NativeProgress, 0, len(expected.Executions))
	for _, e := range expected.Executions {
		progress = append(progress, NativeProgress{e.ExecutionId, e.Generation, e.LastSequence, e.AckSequence})
	}
	return VerifyContinuing(raw, operatorPublicPEM, expected, progress, now)
}

// VerifyContinuing permits only progress already present in the protected native
// journal. The operator's immutable initial plan is not rewritten after cleanup
// events commit. A platform watermark can never exceed this freshly read suffix.
func VerifyContinuing(raw, operatorPublicPEM []byte, expected protocol.PeerRecoveryPlan, progress []NativeProgress, now time.Time) (*Authorization, error) {
	return verifyAuthorization(raw, operatorPublicPEM, expected, progress, now, false)
}

func verifyAuthorization(raw, operatorPublicPEM []byte, expected protocol.PeerRecoveryPlan, progress []NativeProgress, now time.Time, completion bool) (*Authorization, error) {
	reply, err := protocol.DecodePeerRecoveryAuthorization(raw)
	if err != nil || (completion && reply.Status != "COMPLETED") || (!completion && reply.Status != "APPROVED" && reply.Status != "APPLIED") {
		return nil, ErrApproval
	}
	actual, _ := Canonical(reply.Identity)
	want, _ := Canonical(expected.Challenge.Identity)
	verified, err := time.Parse(time.RFC3339Nano, reply.VerifiedAt)
	if err != nil || !bytes.Equal(actual, want) || verified.After(now.Add(5*time.Second)) || now.Sub(verified) > 10*time.Second {
		return nil, ErrApproval
	}
	encoded, err := Canonical(reply.Approval)
	if err != nil {
		return nil, ErrApproval
	}
	var approval *OperatorApproval
	if completion {
		approval, err = VerifyRecordedApproval(encoded, operatorPublicPEM, expected, now)
	} else {
		approval, err = VerifyApproval(encoded, operatorPublicPEM, expected, now)
	}
	if err != nil {
		return nil, err
	}
	// Require complete, unique, non-regressing authority. A server ACK beyond the
	// durable local suffix is evidence of a stale snapshot, never permission to
	// invent events or drop native cleanup obligations.
	if len(reply.ServerWatermarks) != len(expected.Executions) {
		return nil, ErrApproval
	}
	if len(progress) != len(expected.Executions) {
		return nil, ErrApproval
	}
	bounds := map[string]NativeProgress{}
	for _, p := range progress {
		key := p.ExecutionID + "\x00" + p.Generation
		if _, ok := bounds[key]; ok {
			return nil, ErrApproval
		}
		bounds[key] = p
	}
	seen := map[string]bool{}
	for _, w := range reply.ServerWatermarks {
		key := w.ExecutionId + "\x00" + w.Generation
		if seen[key] {
			return nil, ErrApproval
		}
		seen[key] = true
		found := false
		for _, e := range expected.Executions {
			if e.ExecutionId != w.ExecutionId || e.Generation != w.Generation {
				continue
			}
			found = true
			seq, err := strconv.ParseUint(w.ContiguousSequence, 10, 64)
			if err != nil {
				return nil, ErrApproval
			}
			bound, ok := bounds[key]
			if !ok {
				return nil, ErrApproval
			}
			ack, ackErr := strconv.ParseUint(bound.AckSequence, 10, 64)
			last, lastErr := strconv.ParseUint(bound.LastSequence, 10, 64)
			originalAck, _ := strconv.ParseUint(e.AckSequence, 10, 64)
			originalLast, _ := strconv.ParseUint(e.LastSequence, 10, 64)
			if ackErr != nil || lastErr != nil || ack > last || ack < originalAck || last < originalLast || (completion && ack != last) {
				return nil, ErrApproval
			}
			if seq < ack || seq > last {
				return nil, ErrApproval
			}
		}
		if !found {
			return nil, ErrApproval
		}
	}
	expiry, _ := time.Parse(time.RFC3339Nano, reply.Approval.Manifest.ExpiresAt)
	return &Authorization{approval: approval, verifiedAt: verified, expiresAt: expiry, watermarks: append([]protocol.EventAck(nil), reply.ServerWatermarks...)}, nil
}

func (a *Authorization) Approval() *OperatorApproval {
	if a == nil {
		return nil
	}
	return a.approval
}
func (a *Authorization) Watermarks() []protocol.EventAck {
	if a == nil {
		return nil
	}
	return append([]protocol.EventAck(nil), a.watermarks...)
}
func (a *Authorization) Current(now time.Time) bool {
	return a != nil && a.approval != nil && a.expiresAt.After(now) && !a.verifiedAt.After(now.Add(5*time.Second)) && now.Sub(a.verifiedAt) <= 10*time.Second
}

// Completion cannot be used as Docker mutation authorization.
type Completion struct{ authorization *Authorization }

func VerifyCompletion(raw, publicPEM []byte, expected protocol.PeerRecoveryPlan, progress []NativeProgress, now time.Time) (*Completion, error) {
	// Completion verifies historical approval, not renewed mutation permission.
	// Its fresh server reply must agree exactly with the fully ACKed native facts.
	a, err := verifyAuthorization(raw, publicPEM, expected, progress, now, true)
	if err != nil {
		return nil, err
	}
	return &Completion{authorization: a}, nil
}
func (c *Completion) Current(now time.Time) bool {
	return c != nil && c.authorization != nil && c.authorization.approval != nil && !c.authorization.verifiedAt.After(now.Add(5*time.Second)) && now.Sub(c.authorization.verifiedAt) <= 10*time.Second
}
func (c *Completion) ApprovalHash() string {
	if c == nil {
		return ""
	}
	return c.authorization.approval.Hash()
}

// RecordedApproval is immutable evidence for the journal's finalization checks.
// It does not expose an Authorization and cannot renew Docker mutation access.
func (c *Completion) RecordedApproval() *OperatorApproval {
	if c == nil || c.authorization == nil {
		return nil
	}
	return c.authorization.approval
}
