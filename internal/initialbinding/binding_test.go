package initialbinding

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"testing"
	"time"
)

func TestIndependentFirstBindingScope(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	id := protocol.HostIdentity{HostId: "host", KeyId: "key", KeyVersion: "1", SessionEpoch: "1"}
	q := Request{Version: Version, BootID: "boot", Nonce: "nonce", SourceCredentialHash: "hash", SourceEndpointIdentity: "old", TargetEndpointIdentity: "new"}
	original := Binding{Request: q, InstallationID: "installation", TenantID: "tenant", Identity: id, IssuedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	encode := func(b Binding) []byte {
		raw, _ := json.Marshal(b)
		canonical, _ := protocol.CanonicalizeJSON(raw)
		v := Certificate{b, base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte(Domain), canonical...)))}
		out, _ := json.Marshal(v)
		return out
	}
	if _, e := Verify(encode(original), q, "installation", "tenant", id, pub, now); e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*Binding){"peer": func(b *Binding) { b.TargetEndpointIdentity = "replacement" }, "credential": func(b *Binding) { b.SourceCredentialHash = "replacement" }, "host": func(b *Binding) { b.Identity.HostId = "other" }, "session": func(b *Binding) { b.Identity.SessionEpoch = "2" }, "boot": func(b *Binding) { b.BootID = "replacement" }, "nonce": func(b *Binding) { b.Nonce = "replacement" }, "installation": func(b *Binding) { b.InstallationID = "other" }, "expired": func(b *Binding) { b.ExpiresAt = now.Add(-time.Millisecond).Format(time.RFC3339Nano) }, "overlong": func(b *Binding) { b.ExpiresAt = now.Add(time.Hour).Format(time.RFC3339Nano) }} {
		t.Run(name, func(t *testing.T) {
			b := original
			change(&b)
			if _, e := Verify(encode(b), q, "installation", "tenant", id, pub, now); e == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, e := Verify(encode(original), q, "installation", "tenant", id, other, now); e == nil {
		t.Fatal("forged issuer")
	}
}
