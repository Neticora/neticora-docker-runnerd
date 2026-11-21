//go:build linux

package execution

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
)

func TestIndependentQualificationBindsCurrentDiskExecution(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2026-10-25T12:00:00Z")
	fixtures, err := os.ReadFile("../../api/fixtures/validation.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID    string         `json:"id"`
		Value map[string]any `json:"value"`
	}
	json.Unmarshal(fixtures, &cases)
	var policy, caps map[string]any
	for _, f := range cases {
		if f.ID == "customer-managed-policy-1.1" {
			policy = f.Value
		}
		if caps == nil {
			if v, ok := f.Value["capabilities"].(map[string]any); ok {
				caps = v
			}
		}
	}
	caps["endpointIdentity"] = "engine-a"
	caps["hardStorageLimit"] = false
	caps["dockerBuild"] = false
	delete(caps, "observedAt")
	delete(caps, "probeGeneration")
	stable, _ := json.Marshal(caps)
	stable, _ = protocol.CanonicalizeJSON(stable)
	hash := sha256.Sum256(stable)
	caps["observedAt"] = now.Format(wireTime)
	caps["probeGeneration"] = "1"
	policyRaw, _ := json.Marshal(policy)
	capsRaw, _ := json.Marshal(caps)
	command := storetest.Object(t, storetest.Start(t, "qualified"))
	spec := command["spec"].(map[string]any)
	spec["templateVersion"] = "linux-github-disk-v1"
	spec["hostPlatform"].(map[string]any)["build"] = caps["host"].(map[string]any)["build"]
	manifest := map[string]any{"version": "runnerd07-qualification-v1", "storageEnforcement": "soft", "tenantId": "tenant-a", "hostId": "host-a", "sessionEpoch": "1", "endpointIdentity": "engine-a", "agentVersion": Version(), "expiresAt": now.Add(time.Hour).Format(wireTime), "verifiedAt": now.Format(wireTime), "capabilitiesHash": hex.EncodeToString(hash[:]), "policy": policy, "specs": map[string]any{"small": spec}, "imageVerificationReference": "independent image verification", "providerQualificationReference": "independent installed-host workflow"}
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	credentials := Credentials{TenantID: "tenant-a", EndpointIdentity: "engine-a", Identity: protocol.HostIdentity{HostId: "host-a", SessionEpoch: "1"}}
	c := config.Config{Connection: &config.Connection{RunnerDeploymentID: "pool-a"}, Execution: &config.Execution{RunnerSize: "small", StorageRoot: "/private/executions"}}
	sign := func() []byte {
		raw, _ := json.Marshal(manifest)
		raw, _ = protocol.CanonicalizeJSON(raw)
		result, _ := json.Marshal(map[string]any{"manifest": json.RawMessage(raw), "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, raw))})
		return result
	}
	if _, err := verifyQualification(sign(), public, capsRaw, policyRaw, c, credentials, now); err != nil {
		t.Fatal("current independently signed tuple rejected", err)
	}
	for _, field := range []string{"tenantId", "hostId", "sessionEpoch", "endpointIdentity", "agentVersion", "capabilitiesHash"} {
		original := manifest[field]
		manifest[field] = "changed"
		if _, err := verifyQualification(sign(), public, capsRaw, policyRaw, c, credentials, now); err == nil {
			t.Fatal("changed scope accepted", field)
		}
		manifest[field] = original
	}
	for _, at := range []time.Time{now.Add(-time.Second), now.Add(2 * time.Hour)} {
		if _, err := verifyQualification(sign(), public, capsRaw, policyRaw, c, credentials, at); err == nil {
			t.Fatal("future/expired acceptance accepted")
		}
	}
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ = x509.MarshalPKIXPublicKey(wrong)
	if _, err := verifyQualification(sign(), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), capsRaw, policyRaw, c, credentials, now); err == nil {
		t.Fatal("wrong trust accepted")
	}
}

func TestReadinessSeparatesQualificationAdmissionDrainAndExpiry(t *testing.T) {
	now := time.Now()
	expired := false
	r := &HostRemote{PolicyGeneration: func() string { return "1" }, CheckQualification: func() error {
		if expired {
			return ErrQualification
		}
		return nil
	}}
	r.observeAdmission(protocol.ConfigResponse{AdmissionEnabled: true, Policy: protocol.LocalPolicy{Generation: "1"}}, nil)
	c := &Controller{Remote: r, Drained: func() bool { return false }}
	c.status.Store("ready")
	if report := c.Readiness(time.Now()); !report.RuntimeQualified || !report.PlatformAdmissionEnabled || len(report.DispatchBlockers) != 0 {
		t.Fatal(report)
	}
	c.Drained = func() bool { return true }
	if report := c.Readiness(now.Add(time.Minute)); !report.RuntimeQualified || report.PlatformAdmissionEnabled || len(report.DispatchBlockers) < 2 {
		t.Fatal(report)
	}
	expired = true
	if c.Readiness(time.Now()).RuntimeQualified {
		t.Fatal("expired acceptance remained qualified")
	}
}

func TestQualificationCannotBeReusedForDifferentExecutionTemplate(t *testing.T) {
	a := protocol.ExecutionSpec{PoolId: "pool", TemplateVersion: "linux-github-disk-v1", Resources: protocol.ResourceBudget{CpuMillis: "1000", MemoryBytes: "1000", StorageBytes: "1000", Slots: "1"}}
	b := a
	b.ExecutionId = "new-execution"
	b.AttemptId = "new-attempt"
	b.Generation = "2"
	b.SpecHash = "new-hash"
	b.AuthorizationExpiresAt = "new-time"
	if !sameQualifiedTemplate(a, b) {
		t.Fatal("dynamic execution identity changed immutable template")
	}
	b.Resources.CpuMillis = "2000"
	if sameQualifiedTemplate(a, b) {
		t.Fatal("larger workload reused smaller qualification")
	}
	b = a
	b.TemplateVersion = "linux-github-process-v1"
	if sameQualifiedTemplate(a, b) {
		t.Fatal("legacy template reused disk acceptance")
	}
}
