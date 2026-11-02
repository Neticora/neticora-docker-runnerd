// Package identity constructs transient host proofs. Callers own protected key
// storage and durable enrollment/session identities; this package never writes keys.
package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

func public(private ed25519.PrivateKey) (string, string, error) {
	if len(private) != ed25519.PrivateKeySize {
		return "", "", errors.New("invalid host private key")
	}
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		return "", "", errors.New("invalid host public key")
	}
	digest := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), hex.EncodeToString(digest[:]), nil
}
func sign(private ed25519.PrivateKey, payload any) (string, error) {
	if len(private) != ed25519.PrivateKeySize {
		return "", errors.New("invalid host private key")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	canonical, err := protocol.CanonicalizeJSON(raw)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, canonical)), nil
}

// Enrollment signs request identity, hashed enrollment token and SPKI fingerprint.
// Persist requestID and the key before sending; retry the identical request on loss.
func Enrollment(private ed25519.PrivateKey, requestID, token string) (protocol.Outbound, error) {
	pub, fingerprint, err := public(private)
	if err != nil {
		return protocol.Outbound{}, err
	}
	digest := sha256.Sum256([]byte(token))
	proof, err := sign(private, map[string]any{"purpose": "neticora-host-enroll-v1", "requestId": requestID, "tokenHash": hex.EncodeToString(digest[:]), "publicKeyFingerprint": fingerprint})
	if err != nil {
		return protocol.Outbound{}, err
	}
	return protocol.EncodeValidated("EnrollmentRequest", map[string]any{"requestId": requestID, "enrollmentToken": token, "publicKey": pub, "proof": proof})
}

// Assertion uses fixed audience and a maximum 60-second lifetime. jti must be
// freshly random for each token request; retries use a fresh assertion.
func Assertion(private ed25519.PrivateKey, host protocol.HostIdentity, bootID, jti string, now time.Time) (protocol.Outbound, error) {
	if _, _, err := public(private); err != nil {
		return protocol.Outbound{}, err
	}
	identityJSON, err := json.Marshal(host)
	if err != nil {
		return protocol.Outbound{}, err
	}
	if err = protocol.ValidateInboundJSON("HostIdentity", identityJSON); err != nil {
		return protocol.Outbound{}, err
	}
	validNonce := func(value string, maximum int) bool {
		return len(value) >= 16 && len(value) <= maximum && strings.IndexFunc(value, func(c rune) bool {
			return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-')
		}) == -1
	}
	if !validNonce(jti, 256) || !validNonce(bootID, 128) {
		return protocol.Outbound{}, errors.New("invalid assertion identity")
	}
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": host.KeyId})
	claims, _ := json.Marshal(map[string]any{"iss": host.HostId, "sub": host.HostId, "aud": "neticora-runner-hosts", "iat": now.Unix(), "exp": now.Unix() + 60, "jti": jti, "bootId": bootID, "sessionEpoch": host.SessionEpoch, "keyVersion": host.KeyVersion})
	data := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	assertion := data + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(data)))
	return protocol.EncodeValidated("TokenRequest", map[string]any{"assertion": assertion})
}

// Rotation requires proof from both keys and binds the current server identity.
// Persist requestID and the next key before transmission; retain the old key until
// the identical rotation result is durably stored.
func Rotation(current, next ed25519.PrivateKey, host protocol.HostIdentity, requestID string) (protocol.Outbound, error) {
	pub, fingerprint, err := public(next)
	if err != nil {
		return protocol.Outbound{}, err
	}
	payload := map[string]any{"purpose": "neticora-host-rotate-v1", "requestId": requestID, "identity": host, "newPublicKeyFingerprint": fingerprint}
	oldProof, err := sign(current, payload)
	if err != nil {
		return protocol.Outbound{}, err
	}
	newProof, err := sign(next, payload)
	if err != nil {
		return protocol.Outbound{}, err
	}
	return protocol.EncodeValidated("KeyRotationRequest", map[string]any{"requestId": requestID, "newPublicKey": pub, "currentKeyProof": oldProof, "newKeyProof": newProof})
}
