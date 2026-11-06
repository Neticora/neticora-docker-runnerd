// Package peerrecovery verifies purpose-scoped operator approval. Signature
// verification alone is not platform commitment or Docker mutation authority.
package peerrecovery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

var ErrApproval = errors.New("peer recovery approval rejected; ownership remains fenced")

// OperatorApproval has an immutable verified snapshot. A caller must separately
// fetch its committed authorization under the current authenticated host session.
type OperatorApproval struct {
	raw  []byte
	hash string
}

func Canonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrApproval
	}
	raw, err = protocol.CanonicalizeJSON(raw)
	if err != nil {
		return nil, ErrApproval
	}
	return raw, nil
}

func Hash(value any) (string, error) {
	raw, err := Canonical(value)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}

func verify(publicPEM []byte, value any, signature string) error {
	block, rest := pem.Decode(bytes.ReplaceAll(publicPEM, []byte(`\n`), []byte("\n")))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return ErrApproval
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return ErrApproval
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return ErrApproval
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || base64.RawURLEncoding.EncodeToString(sig) != signature {
		return ErrApproval
	}
	raw, err := Canonical(value)
	if err != nil || !ed25519.Verify(key, raw, sig) {
		return ErrApproval
	}
	return nil
}

func ValidatePlan(plan protocol.PeerRecoveryPlan) error {
	if _, err := protocol.EncodeValidated("PeerRecoveryPlan", plan); err != nil {
		return ErrApproval
	}
	if plan.SourceEndpointIdentity == plan.TargetEndpointIdentity {
		return ErrApproval
	}
	current, err := strconv.ParseUint(plan.Challenge.Identity.SessionEpoch, 10, 64)
	if err != nil {
		return ErrApproval
	}
	ids, events := map[string]bool{}, map[string]bool{}
	for _, execution := range plan.Executions {
		key := execution.ExecutionId + "\x00" + execution.Generation
		if ids[key] {
			return ErrApproval
		}
		ids[key] = true
		origin, err := strconv.ParseUint(execution.OriginalSessionEpoch, 10, 64)
		if err != nil || origin > current {
			return ErrApproval
		}
		last, err := strconv.ParseUint(execution.LastSequence, 10, 64)
		if err != nil {
			return ErrApproval
		}
		ack, err := strconv.ParseUint(execution.AckSequence, 10, 64)
		if err != nil || ack > last || last-ack != uint64(len(execution.PendingEvents)) {
			return ErrApproval
		}
		for _, event := range execution.PendingEvents {
			if ack == ^uint64(0) {
				return ErrApproval
			}
			ack++
			if event.Sequence != strconv.FormatUint(ack, 10) || events[event.EventId] {
				return ErrApproval
			}
			events[event.EventId] = true
		}
		if ref := execution.OriginalRuntimeRef; ref != nil {
			if ref.ExecutionId != execution.ExecutionId || ref.Generation != execution.Generation || ref.SpecHash != execution.SpecHash || ref.Scope != plan.SourceEndpointIdentity || ref.Engine != "docker" {
				return ErrApproval
			}
			if execution.ObservedState != "unknown" && execution.ObservedResourceId != nil && ref.ResourceId != *execution.ObservedResourceId {
				return ErrApproval
			}
		}
		if execution.ObservedState != "absent" && execution.ObservedState != "unknown" && execution.ObservedResourceId == nil {
			return ErrApproval
		}
		if execution.ObservedState == "absent" && execution.ObservedResourceId != nil {
			return ErrApproval
		}
	}
	return nil
}

func freshPlan(plan protocol.PeerRecoveryPlan, now time.Time) bool {
	expires, err := time.Parse(time.RFC3339Nano, plan.Challenge.ExpiresAt)
	observed, observedErr := time.Parse(time.RFC3339Nano, plan.ObservedAt)
	return err == nil && observedErr == nil && expires.After(now) && !observed.After(now.Add(5*time.Second)) && now.Sub(observed) <= 15*time.Minute
}

func VerifyPlan(raw, hostPublicPEM []byte, challenge protocol.PeerRecoveryChallenge, now time.Time) (protocol.PeerRecoveryPlan, error) {
	signed, err := protocol.DecodeSignedPeerRecoveryPlan(raw)
	if err != nil || ValidatePlan(signed.Plan) != nil {
		return protocol.PeerRecoveryPlan{}, ErrApproval
	}
	a, err := Canonical(challenge)
	if err != nil {
		return protocol.PeerRecoveryPlan{}, ErrApproval
	}
	b, _ := Canonical(signed.Plan.Challenge)
	expires, err := time.Parse(time.RFC3339Nano, challenge.ExpiresAt)
	observed, observedErr := time.Parse(time.RFC3339Nano, signed.Plan.ObservedAt)
	if !bytes.Equal(a, b) || err != nil || observedErr != nil || !expires.After(now) || observed.After(now.Add(5*time.Second)) || now.Sub(observed) > 15*time.Minute || verify(hostPublicPEM, signed.Plan, signed.Signature) != nil {
		return protocol.PeerRecoveryPlan{}, ErrApproval
	}
	return signed.Plan, nil
}

func VerifyApproval(raw, operatorPublicPEM []byte, expected protocol.PeerRecoveryPlan, now time.Time) (*OperatorApproval, error) {
	signed, err := protocol.DecodeSignedPeerRecoveryApproval(raw)
	if err != nil || ValidatePlan(signed.Manifest.Plan) != nil || ValidatePlan(expected) != nil || !freshPlan(expected, now) {
		return nil, ErrApproval
	}
	manifest := signed.Manifest
	want, err := Hash(expected)
	if err != nil {
		return nil, ErrApproval
	}
	got, err := Hash(manifest.Plan)
	if err != nil || got != want || manifest.PlanHash != want || verify(operatorPublicPEM, manifest, signed.Signature) != nil {
		return nil, ErrApproval
	}
	issued, err := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
	if err != nil {
		return nil, ErrApproval
	}
	expires, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if err != nil {
		return nil, ErrApproval
	}
	challengeExpiry, err := time.Parse(time.RFC3339Nano, manifest.Plan.Challenge.ExpiresAt)
	if err != nil || !expires.After(now) || !expires.After(issued) || issued.After(now.Add(5*time.Second)) || expires.Sub(issued) > 15*time.Minute || expires.After(challengeExpiry) || strings.TrimSpace(manifest.AuditReference) == "" {
		return nil, ErrApproval
	}
	if len(manifest.Decisions) != len(manifest.Plan.Executions) {
		return nil, ErrApproval
	}
	decisions := map[string]protocol.PeerRecoveryDecision{}
	for _, decision := range manifest.Decisions {
		key := decision.ExecutionId + "\x00" + decision.Generation
		if _, ok := decisions[key]; ok {
			return nil, ErrApproval
		}
		decisions[key] = decision
	}
	for _, execution := range manifest.Plan.Executions {
		decision, ok := decisions[execution.ExecutionId+"\x00"+execution.Generation]
		if !ok {
			return nil, ErrApproval
		}
		if decision.Action != "verify-absent" && decision.AbsenceWitness != nil {
			return nil, ErrApproval
		}
		switch decision.Action {
		case "hold":
		case "observe-and-cleanup":
			if execution.CreationClaim != "verified" || (execution.ObservedState != "running" && execution.ObservedState != "exited") || execution.NativeState == "cleaned" {
				return nil, ErrApproval
			}
		case "cleanup":
			if execution.CreationClaim != "verified" || execution.ObservedState == "absent" || execution.ObservedState == "unknown" || execution.NativeState == "cleaned" {
				return nil, ErrApproval
			}
		case "verify-absent":
			if execution.ObservedState != "absent" || execution.CreationClaim != "verified" || execution.OriginalRuntimeRef == nil || decision.AbsenceWitness == nil {
				return nil, ErrApproval
			}
			witnessTime, err := time.Parse(time.RFC3339Nano, decision.AbsenceWitness.ObservedAt)
			if err != nil || witnessTime.After(issued.Add(5*time.Second)) || issued.Sub(witnessTime) > 15*time.Minute {
				return nil, ErrApproval
			}
		case "replay-final-ack":
			if execution.NativeState != "cleaned" || execution.ObservedState != "absent" {
				return nil, ErrApproval
			}
		default:
			return nil, ErrApproval
		}
	}
	canonical, err := Canonical(signed)
	if err != nil {
		return nil, ErrApproval
	}
	hash, err := Hash(signed)
	if err != nil {
		return nil, ErrApproval
	}
	return &OperatorApproval{raw: canonical, hash: hash}, nil
}

func (a *OperatorApproval) Value() (protocol.SignedPeerRecoveryApproval, error) {
	if a == nil || len(a.raw) == 0 {
		return protocol.SignedPeerRecoveryApproval{}, ErrApproval
	}
	return protocol.DecodeSignedPeerRecoveryApproval(bytes.Clone(a.raw))
}
func (a *OperatorApproval) Hash() string {
	if a == nil {
		return ""
	}
	return a.hash
}
