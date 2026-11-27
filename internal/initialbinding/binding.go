// Package initialbinding verifies metadata-only first-admission peer transitions.
// This domain cannot authorize broker operations or recover used hosts.
package initialbinding

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"time"
)

const Version = "runnerd-initial-runtime-binding-v1"
const Domain = "neticora-runnerd-initial-runtime-binding-v1\n"

var ErrRejected = errors.New("initial runtime binding rejected; retain original enrollment")

type Request struct {
	Version                string `json:"version"`
	BootID                 string `json:"bootId"`
	Nonce                  string `json:"nonce"`
	SourceCredentialHash   string `json:"sourceCredentialHash"`
	SourceEndpointIdentity string `json:"sourceEndpointIdentity"`
	TargetEndpointIdentity string `json:"targetEndpointIdentity"`
}
type Binding struct {
	Request
	InstallationID string                `json:"installationId"`
	TenantID       string                `json:"tenantId"`
	Identity       protocol.HostIdentity `json:"identity"`
	IssuedAt       string                `json:"issuedAt"`
	ExpiresAt      string                `json:"expiresAt"`
}
type Certificate struct {
	Binding   Binding `json:"binding"`
	Signature string  `json:"signature"`
}

func Hash(raw []byte) string { v := sha256.Sum256(raw); return hex.EncodeToString(v[:]) }
func Verify(raw []byte, q Request, installation, tenant string, identity protocol.HostIdentity, key ed25519.PublicKey, now time.Time) (Certificate, error) {
	var c Certificate
	if len(raw) > 16384 || len(key) != ed25519.PublicKeySize {
		return c, ErrRejected
	}
	if _, err := protocol.CanonicalizeJSON(raw); err != nil {
		return c, ErrRejected
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return c, ErrRejected
	}
	b := c.Binding
	if b.Request != q || q.Version != Version || b.InstallationID != installation || b.TenantID != tenant || b.Identity != identity || identity.SessionEpoch != "1" || identity.KeyVersion != "1" || q.SourceEndpointIdentity == q.TargetEndpointIdentity {
		return c, ErrRejected
	}
	issued, e1 := time.Parse(time.RFC3339Nano, b.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, b.ExpiresAt)
	if e1 != nil || e2 != nil || issued.After(now) || !expires.After(now) || !expires.After(issued) || expires.Sub(issued) > 10*time.Minute {
		return c, ErrRejected
	}
	body, _ := json.Marshal(b)
	canonical, err := protocol.CanonicalizeJSON(body)
	sig, e := base64.RawURLEncoding.DecodeString(c.Signature)
	if err != nil || e != nil || base64.RawURLEncoding.EncodeToString(sig) != c.Signature || !ed25519.Verify(key, append([]byte(Domain), canonical...), sig) {
		return c, ErrRejected
	}
	return c, nil
}
