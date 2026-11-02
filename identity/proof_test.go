package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"strings"
	"testing"
	"time"
)

func TestEnrollmentRecoveryAndBinding(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	first, err := Enrollment(private, "request-1", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Enrollment(private, "request-1", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("response-loss retry changed request")
	}
	var request struct {
		Proof string `json:"proof"`
	}
	if err = json.Unmarshal(first.Bytes(), &request); err != nil {
		t.Fatal(err)
	}
	other, _ := Enrollment(private, "request-1", "other-token")
	if bytes.Equal(first.Bytes(), other.Bytes()) {
		t.Fatal("token not bound")
	}
	_, fingerprint, _ := public(private)
	object := map[string]any{"purpose": "neticora-host-enroll-v1", "requestId": "request-1", "tokenHash": tokenDigest("secret-token"), "publicKeyFingerprint": fingerprint}
	raw, _ := json.Marshal(object)
	canonical, _ := protocol.CanonicalizeJSON(raw)
	signature, _ := base64.RawURLEncoding.DecodeString(request.Proof)
	if !ed25519.Verify(private.Public().(ed25519.PublicKey), canonical, signature) {
		t.Fatal("invalid enrollment proof")
	}
}
func TestAssertionIdentityAndExpiry(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	host := protocol.HostIdentity{HostId: "host", KeyId: "key", KeyVersion: "1", SessionEpoch: "2"}
	now := time.Unix(1900000000, 0)
	message, err := Assertion(private, host, "boot_0123456789abcdef", "nonce_0123456789abcdef", now)
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Assertion string `json:"assertion"`
	}
	_ = json.Unmarshal(message.Bytes(), &request)
	parts := strings.Split(request.Assertion, ".")
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ed25519.Verify(private.Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("invalid assertion signature")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(raw, &claims)
	if claims["aud"] != "neticora-runner-hosts" || claims["sessionEpoch"] != "2" || claims["exp"].(float64)-claims["iat"].(float64) != 60 {
		t.Fatal("invalid authority claims")
	}
	if _, err := Assertion(nil, host, "boot_0123456789abcdef", "nonce_0123456789abcdef", now); err == nil {
		t.Fatal("invalid key accepted")
	}
}
func TestRotationAndInvalidKeys(t *testing.T) {
	current := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{10}, 32))
	host := protocol.HostIdentity{HostId: "host", KeyId: "key", KeyVersion: "1", SessionEpoch: "2"}
	message, err := Rotation(current, next, host, "rotate-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.ValidateInboundJSON("KeyRotationRequest", message.Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, err := Enrollment(nil, "request", "token"); err == nil {
		t.Fatal("nil key accepted")
	}
}

func tokenDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func TestServerPolicyCannotWidenLocalCeilings(t *testing.T) {
	local := protocol.LocalPolicy{Generation: "1", AllowedProfiles: []string{"standard"}, AllowedTrustClasses: []protocol.LocalPolicyAllowedTrustClasses{"trusted"}, Limits: protocol.ResourceBudget{CpuMillis: "100", MemoryBytes: "100", StorageBytes: "100", Slots: "1"}}
	remote := protocol.LocalPolicy{Generation: "2", AllowedProfiles: []string{"standard", "isolated"}, AllowedTrustClasses: []protocol.LocalPolicyAllowedTrustClasses{"trusted", "untrusted"}, Limits: protocol.ResourceBudget{CpuMillis: "1000", MemoryBytes: "50", StorageBytes: "1000", Slots: "10"}}
	narrowed, err := NarrowPolicy(local, remote)
	if err != nil {
		t.Fatal(err)
	}
	if len(narrowed.AllowedProfiles) != 1 || len(narrowed.AllowedTrustClasses) != 1 || narrowed.Limits.CpuMillis != "100" || narrowed.Limits.MemoryBytes != "50" || narrowed.Limits.Slots != "1" {
		t.Fatal("server widened local policy")
	}
	if local.Generation != "1" || local.Limits.MemoryBytes != "100" {
		t.Fatal("local policy mutated")
	}
	remote.Limits.CpuMillis = "18446744073709551616"
	if _, err := NarrowPolicy(local, remote); err == nil {
		t.Fatal("overflow accepted")
	}
}
