package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"slices"
	"strconv"
	"time"
)

const DisposalVersion = "runnerd-broker-disposal-v1"
const DisposalChallengeDomain = "neticora-runnerd-broker-disposal-challenge-v1\n"
const DisposalDomain = "neticora-runnerd-broker-disposal-v1\n"

type DisposalChallenge struct {
	Version          string   `json:"version"`
	Binding          Binding  `json:"binding"`
	ResourceID       string   `json:"resourceId"`
	OperationIDs     []string `json:"operationIds"`
	Nonce            string   `json:"nonce"`
	NotBefore        string   `json:"notBefore"`
	ExpiresAt        string   `json:"expiresAt"`
	RecoveryID       string   `json:"recoveryId,omitempty"`
	RetirementPolicy string   `json:"retirementPolicy,omitempty"`
}
type SignedDisposalChallenge struct {
	Challenge DisposalChallenge `json:"challenge"`
	Signature string            `json:"signature"`
}
type Disposal struct {
	Version       string                     `json:"version"`
	ChallengeHash string                     `json:"challengeHash"`
	Binding       Binding                    `json:"binding"`
	ResourceID    string                     `json:"resourceId"`
	OperationIDs  []string                   `json:"operationIds"`
	Boot          string                     `json:"boot"`
	Revision      string                     `json:"revision"`
	State         string                     `json:"state"`
	ObservedAt    string                     `json:"observedAt"`
	RecoveryID    string                     `json:"recoveryId,omitempty"`
	Retirement    *katalinux.RetirementProof `json:"retirement,omitempty"`
}
type SignedDisposal struct {
	Challenge SignedDisposalChallenge `json:"challenge"`
	Disposal  Disposal                `json:"disposal"`
	Signature string                  `json:"signature"`
}

func DecodeDisposalChallenge(raw []byte) (SignedDisposalChallenge, error) {
	var v SignedDisposalChallenge
	err := decode(raw, &v)
	return v, err
}
func DecodeDisposal(raw []byte) (SignedDisposal, error) {
	var v SignedDisposal
	err := decode(raw, &v)
	return v, err
}

func verifyDisposalChallenge(s SignedDisposalChallenge, key ed25519.PublicKey, now time.Time) error {
	c := s.Challenge
	start, e1 := time.Parse(time.RFC3339Nano, c.NotBefore)
	end, e2 := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if c.Version != DisposalVersion || !c.Binding.valid() || (c.ResourceID != "" && !digest(c.ResourceID)) || !digest(c.Nonce) || len(c.OperationIDs) == 0 || len(c.OperationIDs) > 16 || !slices.IsSorted(c.OperationIDs) || e1 != nil || e2 != nil || !end.After(start) || end.Sub(start) > time.Minute || now.Before(start) || !now.Before(end) {
		return ErrRejected
	}
	if (c.RetirementPolicy != "" && c.RetirementPolicy != katalinux.RetirementPolicy) || (c.RetirementPolicy != "" && (c.ResourceID == "" || c.RecoveryID != "")) {
		return ErrRejected
	}
	if c.RecoveryID != "" && !digest(c.RecoveryID) {
		return ErrRejected
	}
	for i, id := range c.OperationIDs {
		if !digest(id) || (i > 0 && id == c.OperationIDs[i-1]) {
			return ErrRejected
		}
	}
	raw, err := canonical(c)
	sig, e3 := base64.StdEncoding.Strict().DecodeString(s.Signature)
	if err != nil || e3 != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(DisposalChallengeDomain), raw...), sig) {
		return ErrRejected
	}
	return nil
}

// Attest is observational. It cannot stop/remove, adopt foreign resources or
// convert an unknown operation into a replacement. Signature covers fresh,
// independently observed absence and the exact platform commitment set.
func (e *physicalExecutor) Attest(ctx context.Context, s SignedDisposalChallenge, key ed25519.PrivateKey) (SignedDisposal, error) {
	if len(key) != ed25519.PrivateKeySize || e.handoffs == nil || verifyDisposalChallenge(s, e.key, e.now()) != nil {
		return SignedDisposal{}, ErrRejected
	}
	e.ledger.mu.Lock()
	defer e.ledger.mu.Unlock()
	c := s.Challenge
	state, p, err := e.loadOriginal(Lookup{ExecutionID: c.Binding.ExecutionID, Generation: c.Binding.Generation, SpecHash: c.Binding.SpecHash, ResourceID: c.ResourceID})
	if err != nil {
		return SignedDisposal{}, err
	}
	if state.Binding != c.Binding || state.ResourceID != c.ResourceID {
		return SignedDisposal{}, ErrQuarantined
	}
	phase, revision := state.State, state.Revision
	if c.RecoveryID != "" {
		record, recoveryErr := e.bootRecord(state)
		if recoveryErr != nil || record.Phase != "DISPOSED" || record.Authority.Certificate.ID != c.RecoveryID {
			return SignedDisposal{}, ErrQuarantined
		}
		if err = e.bootAbsent(ctx, state, p, record); err != nil {
			return SignedDisposal{}, err
		}
		phase = "RECOVERY_DISPOSED"
	} else if state.Boot != e.boot || (state.State != "REMOVED" && state.State != "NEVER_CREATED") || state.Pending != "" {
		return SignedDisposal{}, ErrQuarantined
	}
	ids := make([]string, 0, len(state.Operations))
	for _, op := range state.Operations {
		if c.RecoveryID == "" && !state.Completed[op.OperationID] {
			return SignedDisposal{}, ErrQuarantined
		}
		ids = append(ids, op.OperationID)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, c.OperationIDs) {
		return SignedDisposal{}, ErrConflict
	}
	if c.RecoveryID != "" {
		revision = strconv.Itoa(len(ids))
	} else if state.State == "NEVER_CREATED" {
		err = e.unstartedAbsence(ctx, state, p)
	} else {
		err = e.absence(ctx, state, p)
	}
	if err != nil {
		return SignedDisposal{}, err
	}
	if verifyDisposalChallenge(s, e.key, e.now()) != nil {
		return SignedDisposal{}, ErrRejected
	}
	raw, _ := canonical(s)
	sum := sha256.Sum256(raw)
	proof := Disposal{Version: DisposalVersion, ChallengeHash: hex.EncodeToString(sum[:]), Binding: state.Binding, ResourceID: state.ResourceID, OperationIDs: ids, Boot: e.boot, Revision: revision, State: phase, RecoveryID: c.RecoveryID, ObservedAt: e.now().UTC().Format("2006-01-02T15:04:05.000Z")}
	if state.Spec.IsolationProfile == "isolated" && c.ResourceID != "" && c.RecoveryID == "" {
		provider, ok := e.kata.(interface {
			Retirement(context.Context, string, dockerengine.Plan) (*katalinux.RetirementProof, error)
		})
		if ok {
			proof.Retirement, err = provider.Retirement(ctx, state.ResourceID, p)
			if err != nil {
				return SignedDisposal{}, err
			}
		}
	}
	if c.RetirementPolicy != "" {
		if proof.Retirement == nil || proof.Retirement.Policy != c.RetirementPolicy || proof.Retirement.OperationID != state.Operations["RemoveExecution"].OperationID {
			return SignedDisposal{}, ErrQuarantined
		}
	} else if proof.Retirement != nil {
		return SignedDisposal{}, ErrRejected
	}
	raw, err = canonical(proof)
	if err != nil {
		return SignedDisposal{}, err
	}
	return SignedDisposal{Challenge: s, Disposal: proof, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(DisposalDomain), raw...)))}, nil
}
