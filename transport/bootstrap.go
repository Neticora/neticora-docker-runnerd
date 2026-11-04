package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

// BootstrapBinding pins delivery to the same persisted physical start attempt.
// Its encryption key is separate from enrollment/signing keys. The caller must
// protect the private key outside the journal and erase plaintext after use.
type BootstrapBinding struct {
	TenantID       string `json:"tenantId"`
	HostID         string `json:"hostId"`
	ExecutionID    string `json:"executionId"`
	Generation     string `json:"generation"`
	StartRequestID string `json:"startRequestId"`
	SpecHash       string `json:"specHash"`
	ExpiresAt      string `json:"expiresAt"`
}

// OpenBootstrap opens the runnerd05-sealed-v1 envelope. It does not authorize
// execution: the caller still checks current command, policy and local controls.
func OpenBootstrap(encoded string, private *ecdh.PrivateKey, expected BootstrapBinding, now time.Time) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, errors.New("invalid or expired bootstrap envelope") }
	if private == nil || private.Curve() != ecdh.X25519() || len(encoded) > 65536 {
		return fail()
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fail()
	}
	// Strict byte decoder rejects duplicate keys, malformed Unicode and unknown fields.
	var envelope struct {
		BootstrapBinding
		Version    string `json:"version"`
		Recipient  string `json:"recipient"`
		Ephemeral  string `json:"ephemeral"`
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	}
	if err = protocol.Validate("BootstrapEnvelope", raw); err != nil {
		return fail()
	}
	if err = json.Unmarshal(raw, &envelope); err != nil {
		return fail()
	}
	expires, err := time.Parse(time.RFC3339Nano, envelope.ExpiresAt)
	if err != nil || !expires.After(now) || envelope.BootstrapBinding != expected || envelope.Version != "runnerd05-sealed-v1" ||
		envelope.Recipient != base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()) {
		return fail()
	}
	peerRaw, err := base64.RawURLEncoding.DecodeString(envelope.Ephemeral)
	if err != nil {
		return fail()
	}
	peer, err := ecdh.X25519().NewPublicKey(peerRaw)
	if err != nil {
		return fail()
	}
	secret, err := private.ECDH(peer)
	if err != nil {
		return fail()
	}
	defer clear(secret)
	var context map[string]any
	if err = json.Unmarshal(raw, &context); err != nil {
		return fail()
	}
	delete(context, "nonce")
	delete(context, "ciphertext")
	contextRaw, err := json.Marshal(context)
	if err != nil {
		return fail()
	}
	aad, err := protocol.CanonicalizeJSON(contextRaw)
	if err != nil {
		return fail()
	}
	salt := sha256.Sum256(aad)
	key, err := hkdf.Key(sha256.New, secret, salt[:], "neticora-runnerd-bootstrap-v1", 32)
	if err != nil {
		return fail()
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fail()
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fail()
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return fail()
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return fail()
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return fail()
	}
	return plaintext, nil
}
