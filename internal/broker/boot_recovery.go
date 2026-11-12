package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

const BootRecoveryVersion = "runnerd-broker-boot-recovery-v1"
const BootChallengeDomain = "neticora-runnerd-broker-boot-challenge-v1\n"
const BootRecoveryDomain = "neticora-runnerd-broker-boot-recovery-v1\n"

var ErrBootRecovery = errors.New("explicit broker boot recovery required")

// Boot recovery is cleanup-only, on the SAME engine and installation/session.
// Original physical records, receipts and consumed challenges are never edited.
type BootChallenge struct {
	KataAnchor         string   `json:"kataAnchor,omitempty"`
	EngineAnchor       string   `json:"engineAnchor"`
	ToEndpointIdentity string   `json:"toEndpointIdentity"`
	PreviousRecoveryID string   `json:"previousRecoveryId"`
	Version            string   `json:"version"`
	Binding            Binding  `json:"binding"`
	FromBoot           string   `json:"fromBoot"`
	ToBoot             string   `json:"toBoot"`
	StateHash          string   `json:"stateHash"`
	ResourceID         string   `json:"resourceId"` // Original durable ID, possibly unknown.
	TargetID           string   `json:"targetId"`   // Independently inspected original candidate.
	OperationIDs       []string `json:"operationIds"`
	Nonce              string   `json:"nonce"`
	ExpiresAt          string   `json:"expiresAt"`
}
type SignedBootChallenge struct {
	Challenge BootChallenge `json:"challenge"`
	Signature string        `json:"signature"`
}
type BootCertificate struct {
	Version   string              `json:"version"`
	Operation string              `json:"operation"`
	ID        string              `json:"id"`
	Challenge SignedBootChallenge `json:"challenge"`
	NotBefore string              `json:"notBefore"`
	ExpiresAt string              `json:"expiresAt"`
}
type SignedBootCertificate struct {
	Certificate BootCertificate `json:"certificate"`
	Signature   string          `json:"signature"`
}
type bootRecord struct {
	Version    string                `json:"version"`
	Authority  SignedBootCertificate `json:"authority"`
	AcceptedAt string                `json:"acceptedAt"`
	Phase      string                `json:"phase"`
}

func bootHash(v any) string {
	raw, err := canonical(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func signBoot(domain string, v any, key ed25519.PrivateKey) string {
	raw, _ := canonical(v)
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), raw...)))
}
func verifyBoot(domain string, v any, signature string, key ed25519.PublicKey) bool {
	raw, err := canonical(v)
	sig, se := base64.StdEncoding.Strict().DecodeString(signature)
	return err == nil && se == nil && len(key) == ed25519.PublicKeySize && ed25519.Verify(key, append([]byte(domain), raw...), sig)
}
func DecodeBootCertificate(raw []byte) (SignedBootCertificate, error) {
	var v SignedBootCertificate
	err := decode(raw, &v)
	return v, err
}
func (e *physicalExecutor) originalOperations(state physicalRecord) ([]string, error) {
	ids := []string{}
	for _, op := range state.Operations {
		receipt, err := e.ledger.read(op.OperationID)
		if err != nil || receipt.Binding != state.Binding || receipt.Operation != op.Operation {
			return nil, ErrQuarantined
		}
		payload, payloadErr := (ExecutionGrant{Version: ExecutionGrantVersion, Operation: op.Operation, OperationID: op.OperationID, ExpectedRevision: op.ExpectedRevision, ExpectedState: executionState(op.Operation), ResourceID: op.ResourceID, Binding: state.Binding, Spec: state.Spec}).IntentPayload()
		sum := sha256.Sum256(payload)
		if payloadErr != nil || receipt.PayloadHash != hex.EncodeToString(sum[:]) {
			return nil, ErrQuarantined
		}
		root, err := e.ledger.records("challenges")
		if err != nil {
			return nil, err
		}
		var ch Challenge
		err = readRecord(root, op.OperationID, &ch)
		root.Close()
		if err != nil || ch.Version != challengeVersion || ch.Request != op || ch.State != "CONSUMED" || ch.Binding == nil || *ch.Binding != state.Binding || !digest(ch.GrantHash) {
			return nil, ErrQuarantined
		}
		ids = append(ids, op.OperationID)
	}
	slices.Sort(ids)
	if len(ids) == 0 {
		return nil, ErrQuarantined
	}
	return ids, nil
}

// target verifies both immutable ID and deterministic name before authority is
// requested. A different engine is rejected by loadOriginal/endpoint, even if empty.
func (e *physicalExecutor) recoveryEndpoint(ctx context.Context, s physicalRecord) (string, error) {
	if !digest(s.EngineAnchor) {
		return "", ErrQuarantined
	}
	engine, ok := e.runtime.(interface {
		RecoveryDomain(context.Context) (string, error)
	})
	if !ok {
		return "", ErrQuarantined
	}
	anchor, err := engine.RecoveryDomain(ctx)
	if err != nil || anchor != s.EngineAnchor {
		return "", ErrQuarantined
	}
	return e.runtime.Probe(ctx)
}
func (e *physicalExecutor) bootTarget(ctx context.Context, s physicalRecord, p dockerengine.Plan) (string, error) {
	if _, err := e.recoveryEndpoint(ctx, s); err != nil {
		return "", err
	}
	byName, err := e.runtime.Inspect(ctx, s.Name, p)
	if err != nil && !errors.Is(err, dockerengine.ErrAbsent) {
		return "", err
	}
	if s.ResourceID == "" {
		if err == nil {
			if !digest(byName.ID) {
				return "", ErrQuarantined
			}
			return byName.ID, nil
		}
		return "", nil
	}
	if err == nil && byName.ID != s.ResourceID {
		return "", ErrQuarantined
	}
	object, inspectErr := e.runtime.Inspect(ctx, s.ResourceID, p)
	if inspectErr != nil && !errors.Is(inspectErr, dockerengine.ErrAbsent) {
		return "", inspectErr
	}
	if inspectErr == nil && object.ID != s.ResourceID {
		return "", ErrQuarantined
	}
	return s.ResourceID, nil
}
func (e *physicalExecutor) IssueBootChallenge(ctx context.Context, q Lookup, key ed25519.PrivateKey) (SignedBootChallenge, error) {
	e.ledger.mu.Lock()
	defer e.ledger.mu.Unlock()
	s, p, err := e.loadOriginal(q)
	if err != nil {
		return SignedBootChallenge{}, err
	}
	if s.Spec.IsolationProfile == "isolated" {
		k, restoreErr := e.bootKata(s)
		if restoreErr != nil {
			return SignedBootChallenge{}, restoreErr
		}
		if s.ResourceID == "" {
			return SignedBootChallenge{}, ErrQuarantined
		}
		if err = k.Observe(ctx, s.ResourceID, p); err != nil {
			return SignedBootChallenge{}, err
		}
	} else if s.Spec.IsolationProfile != "standard" {
		return SignedBootChallenge{}, ErrQuarantined
	}
	peer, peerErr := e.recoveryEndpoint(ctx, s)
	if peerErr != nil {
		return SignedBootChallenge{}, peerErr
	}
	if (s.Boot == e.boot && peer == s.Binding.EndpointIdentity) || len(key) != ed25519.PrivateKeySize {
		return SignedBootChallenge{}, ErrRejected
	}
	accepted, acceptedErr := e.readBootRecord(s)
	previous := ""
	if acceptedErr == nil {
		if accepted.Authority.Certificate.Challenge.Challenge.ToBoot == e.boot && accepted.Authority.Certificate.Challenge.Challenge.ToEndpointIdentity == peer {
			return accepted.Authority.Certificate.Challenge, nil
		}
		previous = accepted.Authority.Certificate.ID
	} else if !os.IsNotExist(acceptedErr) {
		return SignedBootChallenge{}, acceptedErr
	}
	ids, err := e.originalOperations(s)
	if err != nil {
		return SignedBootChallenge{}, err
	}
	target, err := e.bootTarget(ctx, s, p)
	if err != nil {
		return SignedBootChallenge{}, err
	}
	if previous != "" && accepted.Authority.Certificate.Challenge.Challenge.TargetID != "" {
		oldTarget := accepted.Authority.Certificate.Challenge.Challenge.TargetID
		if target != "" && target != oldTarget {
			return SignedBootChallenge{}, ErrQuarantined
		}
		target = oldTarget
	}
	root, err := e.ledger.records("boot-challenges")
	if err != nil {
		return SignedBootChallenge{}, err
	}
	defer root.Close()
	var old SignedBootChallenge
	err = readRecord(root, recordID(s.Binding), &old)
	if err == nil {
		if old.Challenge.Version != BootRecoveryVersion || old.Challenge.Binding != s.Binding || old.Challenge.StateHash != bootHash(s) {
			return old, ErrQuarantined
		}
		// Preserve every issued nonce, including expired authority that the
		// platform may already have committed. The keyed file is immutable;
		// only the per-execution current pointer advances.
		if archiveErr := e.ledger.writeRecord(root, bootHash(old), old); archiveErr != nil {
			return old, archiveErr
		}
	}
	if err == nil && old.Challenge.KataAnchor == kataRecoveryHash(s) && old.Challenge.StateHash == bootHash(s) && old.Challenge.ToBoot == e.boot && old.Challenge.ToEndpointIdentity == peer && old.Challenge.TargetID == target {
		expiry, parseErr := time.Parse(time.RFC3339Nano, old.Challenge.ExpiresAt)
		if parseErr != nil || !verifyBoot(BootChallengeDomain, old.Challenge, old.Signature, key.Public().(ed25519.PublicKey)) {
			return old, ErrQuarantined
		}
		if e.now().Before(expiry) {
			return old, nil
		}
	} else if err != nil && !os.IsNotExist(err) {
		return old, err
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return old, err
	}
	c := BootChallenge{KataAnchor: kataRecoveryHash(s), EngineAnchor: s.EngineAnchor, ToEndpointIdentity: peer, PreviousRecoveryID: previous, Version: BootRecoveryVersion, Binding: s.Binding, FromBoot: s.Boot, ToBoot: e.boot, StateHash: bootHash(s), ResourceID: s.ResourceID, TargetID: target, OperationIDs: ids, Nonce: hex.EncodeToString(nonce), ExpiresAt: e.now().Add(15 * time.Second).UTC().Format(time.RFC3339Nano)}
	old = SignedBootChallenge{Challenge: c, Signature: signBoot(BootChallengeDomain, c, key)}
	if err = e.ledger.writeRecord(root, bootHash(old), old); err != nil {
		return old, err
	}
	return old, e.ledger.writeRecord(root, recordID(s.Binding), old)
}
func validBootAuthority(a SignedBootCertificate, key ed25519.PublicKey) bool {
	c := a.Certificate
	ch := c.Challenge.Challenge
	return c.Version == BootRecoveryVersion && c.Operation == "RecoverBootCleanup" && c.ID == bootHash(c.Challenge) && ch.Version == BootRecoveryVersion && ch.Binding.valid() && (ch.FromBoot != ch.ToBoot || ch.Binding.EndpointIdentity != ch.ToEndpointIdentity) && (ch.KataAnchor == "" || digest(ch.KataAnchor)) && digest(ch.EngineAnchor) && ch.ToEndpointIdentity != "" && digest(ch.StateHash) && digest(ch.Nonce) && (ch.PreviousRecoveryID == "" || digest(ch.PreviousRecoveryID)) && verifyBoot(BootRecoveryDomain, c, a.Signature, key)
}
func (e *physicalExecutor) bootRecord(s physicalRecord) (bootRecord, error) {
	r, err := e.readBootRecord(s)
	if err == nil && r.Authority.Certificate.Challenge.Challenge.ToBoot != e.boot {
		return r, ErrBootRecovery
	}
	return r, err
}
func (e *physicalExecutor) readBootRecord(s physicalRecord) (bootRecord, error) {
	root, err := e.ledger.records("boot-recoveries")
	if err != nil {
		return bootRecord{}, err
	}
	defer root.Close()
	var record bootRecord
	err = readRecord(root, recordID(s.Binding), &record)
	if err != nil {
		return record, err
	}
	c := record.Authority.Certificate
	ch := c.Challenge.Challenge
	accepted, e1 := time.Parse(time.RFC3339Nano, record.AcceptedAt)
	begin, e2 := time.Parse(time.RFC3339Nano, c.NotBefore)
	end, e3 := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if record.Version != BootRecoveryVersion || !validBootAuthority(record.Authority, e.key) || ch.KataAnchor != kataRecoveryHash(s) || ch.Binding != s.Binding || ch.StateHash != bootHash(s) || ch.FromBoot != s.Boot || ch.EngineAnchor != s.EngineAnchor || ch.ResourceID != s.ResourceID || e1 != nil || e2 != nil || e3 != nil || accepted.Before(begin) || !accepted.Before(end) || end.Sub(begin) > 15*time.Second || !end.After(begin) || (record.Phase != "PENDING" && record.Phase != "DISPOSED") {
		return record, ErrQuarantined
	}
	ids, err := e.originalOperations(s)
	if err != nil || !slices.Equal(ids, ch.OperationIDs) {
		return record, ErrQuarantined
	}

	history, err := e.ledger.records("boot-history")
	if err != nil {
		return record, err
	}
	defer history.Close()
	cursor := record
	seen := map[string]bool{}
	for cursor.Authority.Certificate.Challenge.Challenge.PreviousRecoveryID != "" {
		id := cursor.Authority.Certificate.Challenge.Challenge.PreviousRecoveryID
		if len(seen) >= 1024 || seen[id] {
			return record, ErrQuarantined
		}
		seen[id] = true
		var prior bootRecord
		if readRecord(history, id, &prior) != nil || !validBootAuthority(prior.Authority, e.key) || prior.Authority.Certificate.ID != id || prior.Authority.Certificate.Challenge.Challenge.KataAnchor != kataRecoveryHash(s) || prior.Authority.Certificate.Challenge.Challenge.StateHash != bootHash(s) || prior.Authority.Certificate.Challenge.Challenge.Binding != s.Binding || (prior.Authority.Certificate.Challenge.Challenge.TargetID != "" && prior.Authority.Certificate.Challenge.Challenge.TargetID != cursor.Authority.Certificate.Challenge.Challenge.TargetID) {
			return record, ErrQuarantined
		}
		cursor = prior
	}
	return record, nil
}

// RecoverBoot consumes exact platform authority before its first effect. Retries
// use that original durable record, even after expiry; no replacement authority.
func (e *physicalExecutor) RecoverBoot(ctx context.Context, a SignedBootCertificate) error {
	e.ledger.mu.Lock()
	defer e.ledger.mu.Unlock()
	c := a.Certificate
	ch := c.Challenge.Challenge
	s, p, err := e.loadOriginal(Lookup{ExecutionID: ch.Binding.ExecutionID, Generation: ch.Binding.Generation, SpecHash: ch.Binding.SpecHash, ResourceID: ch.ResourceID})
	if err != nil {
		return err
	}
	if s.Spec.IsolationProfile == "isolated" {
		if _, restoreErr := e.bootKata(s); restoreErr != nil {
			return restoreErr
		}
		if s.ResourceID == "" || ch.KataAnchor == "" || ch.KataAnchor != kataRecoveryHash(s) {
			return ErrQuarantined
		}
	} else if s.Spec.IsolationProfile != "standard" || ch.KataAnchor != "" {
		return ErrQuarantined
	}
	peer, peerErr := e.recoveryEndpoint(ctx, s)
	if peerErr != nil {
		return peerErr
	}
	if s.Boot == e.boot && peer == s.Binding.EndpointIdentity {
		return ErrRejected
	}
	record, err := e.readBootRecord(s)
	newBoot := err == nil && (record.Authority.Certificate.Challenge.Challenge.ToBoot != e.boot || record.Authority.Certificate.Challenge.Challenge.ToEndpointIdentity != peer)
	if os.IsNotExist(err) || newBoot {
		previous := ""
		if newBoot {
			previous = record.Authority.Certificate.ID
		}
		if ch.PreviousRecoveryID != previous {
			return ErrConflict
		}
		if !validBootAuthority(a, e.key) || ch.KataAnchor != kataRecoveryHash(s) || ch.Binding != s.Binding || ch.StateHash != bootHash(s) || ch.FromBoot != s.Boot || ch.ToBoot != e.boot || ch.ToEndpointIdentity != peer || ch.EngineAnchor != s.EngineAnchor || ch.ResourceID != s.ResourceID {
			return ErrRejected
		}
		begin, e1 := time.Parse(time.RFC3339Nano, c.NotBefore)
		end, e2 := time.Parse(time.RFC3339Nano, c.ExpiresAt)
		challengeEnd, e3 := time.Parse(time.RFC3339Nano, ch.ExpiresAt)
		if e1 != nil || e2 != nil || e3 != nil || !end.After(begin) || end.Sub(begin) > 15*time.Second || end.After(challengeEnd) || e.now().Before(begin) || !e.now().Before(end) {
			return ErrRejected
		}
		root, err := e.ledger.records("boot-challenges")
		if err != nil {
			return err
		}
		var original SignedBootChallenge
		err = readRecord(root, recordID(s.Binding), &original)
		root.Close()
		if err != nil || bootHash(original) != bootHash(c.Challenge) {
			return ErrRejected
		}
		ids, err := e.originalOperations(s)
		if err != nil || !slices.Equal(ids, ch.OperationIDs) {
			return ErrQuarantined
		}
		target, err := e.bootTarget(ctx, s, p)
		if err != nil {
			return err
		}
		if newBoot && record.Authority.Certificate.Challenge.Challenge.TargetID != "" {
			oldTarget := record.Authority.Certificate.Challenge.Challenge.TargetID
			if target != "" && target != oldTarget {
				return ErrQuarantined
			}
			target = oldTarget
		}
		if target != ch.TargetID {
			return ErrQuarantined
		}
		if s.Spec.IsolationProfile == "isolated" {
			k, restoreErr := e.bootKata(s)
			if restoreErr != nil {
				return restoreErr
			}
			if err = k.Observe(ctx, s.ResourceID, p); err != nil {
				return err
			}
		}
		if newBoot {
			history, err := e.ledger.records("boot-history")
			if err != nil {
				return err
			}
			var prior bootRecord
			historyErr := readRecord(history, previous, &prior)
			if historyErr == nil && bootHash(prior) != bootHash(record) {
				history.Close()
				return ErrQuarantined
			}
			if historyErr != nil && !os.IsNotExist(historyErr) {
				history.Close()
				return historyErr
			}
			if os.IsNotExist(historyErr) {
				historyErr = e.ledger.writeRecord(history, previous, record)
			}
			history.Close()
			if historyErr != nil {
				return historyErr
			}
		}
		record = bootRecord{Version: BootRecoveryVersion, Authority: a, AcceptedAt: e.now().UTC().Format(time.RFC3339Nano), Phase: "PENDING"}
		root, err = e.ledger.records("boot-recoveries")
		if err != nil {
			return err
		}
		err = e.ledger.writeRecord(root, recordID(s.Binding), record)
		root.Close()
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if bootHash(record.Authority) != bootHash(a) {
		return ErrConflict
	}
	if record.Phase == "DISPOSED" {
		return e.bootAbsent(ctx, s, p, record)
	}
	if observed, endpointErr := e.recoveryEndpoint(ctx, s); endpointErr != nil || observed != ch.ToEndpointIdentity {
		return ErrBootRecovery
	}
	if ch.TargetID != "" {
		object, inspectErr := e.runtime.Inspect(ctx, ch.TargetID, p)
		if inspectErr != nil && !errors.Is(inspectErr, dockerengine.ErrAbsent) {
			return inspectErr
		}
		if inspectErr == nil {
			if object.ID != ch.TargetID {
				return ErrQuarantined
			}
			if object.State == "running" {
				if err = e.runtime.Stop(ctx, ch.TargetID, p); err != nil {
					return err
				}
			}
			object, err = e.runtime.Inspect(ctx, ch.TargetID, p)
			if err != nil || object.State == "running" {
				return ErrQuarantined
			}
			if err = e.runtime.Remove(ctx, ch.TargetID, p); err != nil {
				return err
			}
		}
	}
	if s.Spec.IsolationProfile == "isolated" {
		k, restoreErr := e.bootKata(s)
		if restoreErr != nil {
			return restoreErr
		}
		if err = k.RecoverDispose(ctx, s.ResourceID, p, func() error { return e.bootRuntimeAbsent(ctx, s, p, record) }); err != nil {
			return err
		}
	}
	if e.handoffs != nil && s.Boot == e.boot {
		if s.Operations["CreateExecution"].OperationID != "" {
			err = e.handoffs.Dispose(p)
		} else {
			err = e.handoffs.DisposeUnstarted(p)
		}
		if err != nil {
			return err
		}
	}
	if err = e.bootAbsent(ctx, s, p, record); err != nil {
		return err
	}
	record.Phase = "DISPOSED"
	root, err := e.ledger.records("boot-recoveries")
	if err != nil {
		return err
	}
	defer root.Close()
	return e.ledger.writeRecord(root, recordID(s.Binding), record)
}
func (e *physicalExecutor) bootAbsent(ctx context.Context, s physicalRecord, p dockerengine.Plan, r bootRecord) error {
	if err := e.bootRuntimeAbsent(ctx, s, p, r); err != nil {
		return err
	}
	if e.handoffs != nil {
		var err error
		if s.Boot == e.boot {
			err = e.handoffs.CheckDisposed(p)
		} else {
			err = e.handoffs.BootAbsent(p, s.Boot, s.Operations["CreateExecution"].OperationID != "")
		}
		if err != nil {
			return err
		}
	}
	if s.Spec.IsolationProfile == "isolated" {
		k, err := e.bootKata(s)
		if err != nil {
			return err
		}
		return k.Absence(ctx, s.ResourceID, p)
	}
	return nil
}
func (e *physicalExecutor) bootRuntimeAbsent(ctx context.Context, s physicalRecord, p dockerengine.Plan, r bootRecord) error {
	observed, endpointErr := e.recoveryEndpoint(ctx, s)
	if endpointErr != nil {
		return endpointErr
	}
	if observed != r.Authority.Certificate.Challenge.Challenge.ToEndpointIdentity {
		return ErrBootRecovery
	}
	for _, id := range []string{s.Name, s.ResourceID, r.Authority.Certificate.Challenge.Challenge.TargetID} {
		if id != "" {
			if _, err := e.runtime.Inspect(ctx, id, p); !errors.Is(err, dockerengine.ErrAbsent) {
				return ErrQuarantined
			}
		}
	}
	ids, err := e.runtime.Inventory(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if id == s.ResourceID || id == r.Authority.Certificate.Challenge.Challenge.TargetID {
			return ErrQuarantined
		}
	}
	target := r.Authority.Certificate.Challenge.Challenge.TargetID
	network, ok := e.runtime.(interface {
		VerifyRecoveryNetworkDetached(context.Context, string, string, string) error
	})
	if !ok {
		return ErrQuarantined
	}
	if err = network.VerifyRecoveryNetworkDetached(ctx, target, p.Name, string(p.HostConfig.NetworkMode)); err != nil {
		return err
	}
	observed, endpointErr = e.recoveryEndpoint(ctx, s)
	if endpointErr != nil {
		return endpointErr
	}
	if observed != r.Authority.Certificate.Challenge.Challenge.ToEndpointIdentity {
		return ErrBootRecovery
	}
	return nil
}
