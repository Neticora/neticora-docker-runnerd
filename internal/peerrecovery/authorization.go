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
func VerifyCommitted(raw, operatorPublicPEM []byte, expected protocol.PeerRecoveryPlan, now time.Time) (*Authorization, error) {
	reply, err := protocol.DecodePeerRecoveryAuthorization(raw)
	if err != nil || (reply.Status != "APPROVED" && reply.Status != "APPLIED") {
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
	approval, err := VerifyApproval(encoded, operatorPublicPEM, expected, now)
	if err != nil {
		return nil, err
	}
	// Require complete, unique, non-regressing authority. A server ACK beyond the
	// durable local suffix is evidence of a stale snapshot, never permission to
	// invent events or drop native cleanup obligations.
	if len(reply.ServerWatermarks) != len(expected.Executions) {
		return nil, ErrApproval
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
			ack, _ := strconv.ParseUint(e.AckSequence, 10, 64)
			last, _ := strconv.ParseUint(e.LastSequence, 10, 64)
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
