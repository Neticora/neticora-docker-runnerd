// Package broker implements the versioned execution-broker boundary. Foundation
// operations cannot mutate runtime resources; unsupported operations fail closed.
package broker

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

const Version = "runnerd-broker-v1"
const MaxMessage = 65536

var ErrRejected = errors.New("broker request rejected")
var ErrConflict = errors.New("broker operation conflict")

type Binding struct {
	InstallationID   string `json:"installationId"`
	TenantID         string `json:"tenantId"`
	HostID           string `json:"hostId"`
	SessionEpoch     string `json:"sessionEpoch"`
	EndpointIdentity string `json:"endpointIdentity"`
	ExecutionID      string `json:"executionId"`
	Generation       string `json:"generation"`
	AttemptID        string `json:"attemptId"`
	SpecHash         string `json:"specHash"`
}

type Request struct {
	Version           string                   `json:"version"`
	Operation         string                   `json:"operation"`
	Target            string                   `json:"target,omitempty"`
	Authorization     *SignedGrant             `json:"authorization,omitempty"`
	ExecutionRequest  *ExecutionGrantRequest   `json:"executionRequest,omitempty"`
	ExecutionGrant    *SignedExecutionGrant    `json:"executionGrant,omitempty"`
	ExecutionCommit   *SignedCommit            `json:"executionCommit,omitempty"`
	Lookup            *Lookup                  `json:"lookup,omitempty"`
	MinimumFreeBytes  uint64                   `json:"minimumFreeBytes,omitempty"`
	DisposalChallenge *SignedDisposalChallenge `json:"disposalChallenge,omitempty"`
	BootCertificate   *SignedBootCertificate   `json:"bootCertificate,omitempty"`
}

// Grant uses a separately provisioned authority key. The controller's existing
// enrollment/signing key must never be installed as this authority.
type Grant struct {
	Version   string  `json:"version"`
	Audience  string  `json:"audience"`
	Operation string  `json:"operation"`
	Target    string  `json:"target"`
	Binding   Binding `json:"binding"`
	NotBefore string  `json:"notBefore"`
	ExpiresAt string  `json:"expiresAt"`
}

type SignedGrant struct {
	Grant     Grant  `json:"grant"`
	Signature string `json:"signature"`
}

type Response struct {
	Version       string               `json:"version"`
	Code          string               `json:"code"`
	Ready         bool                 `json:"ready"`
	Capabilities  []string             `json:"capabilities,omitempty"`
	Receipt       *Receipt             `json:"receipt,omitempty"`
	Challenge     *Challenge           `json:"challenge,omitempty"`
	Runtime       *RuntimeState        `json:"runtime,omitempty"`
	Endpoint      string               `json:"endpoint,omitempty"`
	Inventory     []string             `json:"inventory,omitempty"`
	Observation   *dockerengine.Object `json:"observation,omitempty"`
	KataEvidence  json.RawMessage      `json:"kataEvidence,omitempty"`
	Registration  json.RawMessage      `json:"registration,omitempty"`
	Disposal      *SignedDisposal      `json:"disposal,omitempty"`
	BootChallenge *SignedBootChallenge `json:"bootChallenge,omitempty"`
}

func decode(raw []byte, into any) error {
	if len(raw) == 0 || len(raw) > MaxMessage {
		return ErrRejected
	}
	if _, err := protocol.CanonicalizeJSON(raw); err != nil {
		return ErrRejected
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(into) != nil || d.Decode(new(any)) != io.EOF {
		return ErrRejected
	}
	return nil
}

func digest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func (b Binding) valid() bool {
	for _, s := range []string{b.InstallationID, b.TenantID, b.HostID, b.SessionEpoch, b.EndpointIdentity, b.ExecutionID, b.Generation, b.AttemptID} {
		if len(s) == 0 || len(s) > 256 || strings.ContainsAny(s, " \t\r\n\x00/\\") {
			return false
		}
	}
	return digest(b.SpecHash)
}

func grantBytes(g Grant) ([]byte, error) {
	b, err := json.Marshal(g)
	if err != nil {
		return nil, err
	}
	b, err = protocol.CanonicalizeJSON(b)
	return append([]byte("neticora-runnerd-broker-grant-v1\n"), b...), err
}

func verify(r Request, key ed25519.PublicKey, audience string, scope Binding, now time.Time) error {
	if r.Version != Version || r.Operation != "GetOperationStatus" || !digest(r.Target) || r.Authorization == nil || len(key) != ed25519.PublicKeySize {
		return ErrRejected
	}
	g := r.Authorization.Grant
	if g.Version != Version || g.Audience != audience || g.Operation != r.Operation || g.Target != r.Target || !g.Binding.valid() {
		return ErrRejected
	}
	b := g.Binding
	if b.InstallationID != scope.InstallationID || b.TenantID != scope.TenantID || b.HostID != scope.HostID || b.SessionEpoch != scope.SessionEpoch || b.EndpointIdentity != scope.EndpointIdentity {
		return ErrRejected
	}
	start, e1 := time.Parse(time.RFC3339Nano, g.NotBefore)
	end, e2 := time.Parse(time.RFC3339Nano, g.ExpiresAt)
	if e1 != nil || e2 != nil || !end.After(start) || end.Sub(start) > time.Minute || now.Before(start) || !now.Before(end) {
		return ErrRejected
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(r.Authorization.Signature)
	if err != nil {
		return ErrRejected
	}
	message, err := grantBytes(g)
	if err != nil || !ed25519.Verify(key, message, signature) {
		return ErrRejected
	}
	return nil
}
