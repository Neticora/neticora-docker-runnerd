package katalinux

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

func TestSignedProfileRejectsCaseAliasesAndUnsignedOmittedDefaults(t *testing.T) {
	p := profile(blockFixture())
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(p.Manifest)
	body, err = protocol.CanonicalizeJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, body))
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	keyFile, profileFile := filepath.Join(directory, "public.pem"), filepath.Join(directory, "profile.json")
	der, _ := x509.MarshalPKIXPublicKey(public)
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	var original map[string]any
	if json.Unmarshal(body, &original) != nil {
		t.Fatal("fixture decode")
	}
	write := func(outer map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(outer)
		if err := os.WriteFile(profileFile, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(map[string]any{"manifest": original, "signature": signature})
	if _, err := Load(profileFile, keyFile, p.EvidenceDirectory, p.JournalDirectory, p.Base); err != nil {
		t.Fatal("canonical signed fixture refused", err)
	}
	for _, mutate := range []func(map[string]any){
		func(m map[string]any) { m["guestDnsServers"] = []any{} },
		func(m map[string]any) {
			b := m["storage"].(map[string]any)["block"].(map[string]any)
			b["maxConcurrentAllocations"] = 0
		},
		func(m map[string]any) { m["HostKernel"] = m["hostKernel"]; delete(m, "hostKernel") },
	} {
		var value map[string]any
		json.Unmarshal(body, &value)
		mutate(value)
		write(map[string]any{"manifest": value, "signature": signature})
		if _, err := Load(profileFile, keyFile, p.EvidenceDirectory, p.JournalDirectory, p.Base); err == nil {
			t.Fatal("unsigned field transformation accepted")
		}
	}
	write(map[string]any{"Manifest": original, "signature": signature})
	if _, err := Load(profileFile, keyFile, p.EvidenceDirectory, p.JournalDirectory, p.Base); err == nil {
		t.Fatal("case-insensitive envelope accepted")
	}
}
