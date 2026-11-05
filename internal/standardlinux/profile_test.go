package standardlinux

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

func testPolicy(t *testing.T) *Policy {
	t.Helper()
	raw, err := os.ReadFile("../../api/fixtures/validation.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID    string          `json:"id"`
		Value json.RawMessage `json:"value"`
	}
	_ = json.Unmarshal(raw, &cases)
	for _, c := range cases {
		if c.ID == "customer-managed-policy-1.1" {
			p, e := ParsePolicy(c.Value, nil)
			if e != nil {
				t.Fatal(e)
			}
			return p
		}
	}
	t.Fatal("missing policy fixture")
	return nil
}

func TestTrustedProcessOnlyAdmissionAndTemplate(t *testing.T) {
	p := testPolicy(t)
	v := storetest.Object(t, storetest.Start(t, "a"))
	v["spec"].(map[string]any)["templateVersion"] = TemplateVersion
	raw := storetest.Encode(t, "HostCommand", v)
	var start protocol.StartCommand
	_ = json.Unmarshal(raw, &start)
	if err := p.Admit(storetest.Scope, start.Spec, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*protocol.ExecutionSpec){func(s *protocol.ExecutionSpec) { s.DockerBuild = true }, func(s *protocol.ExecutionSpec) { s.TrustClass = "untrusted" }, func(s *protocol.ExecutionSpec) { s.IsolationProfile = "isolated" }, func(s *protocol.ExecutionSpec) { s.PoolId = "other-pool" }, func(s *protocol.ExecutionSpec) { s.PolicyGeneration = "2" }, func(s *protocol.ExecutionSpec) { s.AuthorizationExpiresAt = "2000-01-01T00:00:00.000Z" }} {
		spec := start.Spec
		change(&spec)
		b, _ := json.Marshal(spec)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		h, _ := protocol.PayloadHashJSON("ExecutionSpec", b)
		m["specHash"] = h
		b, _ = json.Marshal(m)
		_ = json.Unmarshal(b, &spec)
		if err := p.Admit(storetest.Scope, spec, time.Now()); err == nil {
			t.Fatal("unsafe spec accepted")
		}
	}
	plan, err := (Settings{ImageRepository: "example/runner", NetworkID: "existing-customer-bridge", BootstrapRoot: "/run/neticora-runnerd/bootstrap", RunnerUID: 1000, PidsLimit: 128}).Plan(storetest.Scope, start.Spec)
	if err != nil || plan.HostConfig.RestartPolicy.Name != "no" || plan.HostConfig.Privileged || len(plan.Config.Env) != 0 || plan.HostConfig.NanoCPUs != 1_000_000_000 || plan.HostConfig.Memory != 1073741824 || *plan.HostConfig.PidsLimit != 128 {
		t.Fatal("unsafe plan", err)
	}
}

func TestPinnedImageSignatureIdentityDigestAndFreshness(t *testing.T) {
	p := testPolicy(t)
	now := time.Now().UTC()
	p.value.Images.TrustExpiresAt = now.Add(time.Hour).Format(time.RFC3339Nano)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	rootRaw, _ := json.Marshal(map[string]any{"version": "neticora-image-key-v1", "rootId": p.value.Images.TrustRootId, "rootVersion": p.value.Images.TrustRootVersion, "issuer": p.value.Images.TrustedIssuer, "subject": p.value.Images.TrustedSubject, "validUntil": now.Add(time.Hour).Format(time.RFC3339Nano), "publicKeyPem": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	h := sha256.Sum256(rootRaw)
	p.value.Images.TrustRootSha256 = hex.EncodeToString(h[:])
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	rootPath := filepath.Join(dir, "root-a-1.json")
	if err := os.WriteFile(rootPath, rootRaw, 0600); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	payload, _ := json.Marshal(map[string]any{"critical": map[string]any{"type": "cosign container image signature", "identity": map[string]any{"docker-reference": "example/runner"}, "image": map[string]any{"docker-manifest-digest": digest}}})
	hash := sha256.Sum256(payload)
	signature, _ := ecdsa.SignASN1(rand.Reader, key, hash[:])
	row := map[string]any{"payload": base64.StdEncoding.EncodeToString(payload), "base64Signature": base64.StdEncoding.EncodeToString(signature)}
	bundle, _ := json.Marshal([]any{row})
	bundlePath := filepath.Join(dir, digest[7:]+".sigstore.json")
	_ = os.WriteFile(bundlePath, bundle, 0600)
	v := ImageVerifier{RootDirectory: dir, BundleDirectory: dir, ProvisionedAt: now.Add(-time.Minute)}
	if err := v.Verify(context.Background(), p, "example/runner", digest, now); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(context.Background(), p, "other/runner", digest, now); err == nil {
		t.Fatal("cross-repository signature accepted")
	}
	if err := v.Verify(context.Background(), p, "example/runner", digest, now.Add(2*time.Hour)); err == nil {
		t.Fatal("stale trust accepted")
	}
	row["base64Signature"] = base64.StdEncoding.EncodeToString([]byte("forged"))
	bundle, _ = json.Marshal([]any{row})
	_ = os.WriteFile(bundlePath, bundle, 0600)
	if err := v.Verify(context.Background(), p, "example/runner", digest, now); err == nil {
		t.Fatal("forged signature accepted")
	}
	_ = os.WriteFile(rootPath, append(rootRaw, ' '), 0600)
	if err := v.Verify(context.Background(), p, "example/runner", digest, now); err == nil {
		t.Fatal("changed root accepted")
	}
}
