package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

func executionFixture(t *testing.T, operation string) (ExecutionGrantRequest, SignedExecutionGrant, ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	v := storetest.Object(t, storetest.Start(t, "a"))["spec"].(map[string]any)
	v["templateVersion"] = "linux-github-process-v1"
	v["authorizationExpiresAt"] = now.Add(time.Minute).Format("2006-01-02T15:04:05.000Z")
	raw, _ := json.Marshal(v)
	hash, err := protocol.PayloadHashJSON("ExecutionSpec", raw)
	if err != nil {
		t.Fatal(err)
	}
	v["specHash"] = hash
	raw, _ = json.Marshal(v)
	spec, err := protocol.DecodeExecutionSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	request := ExecutionGrantRequest{Version: ExecutionGrantVersion, Operation: operation, ExecutionID: spec.ExecutionId, Generation: spec.Generation, ExpectedRevision: "0", Challenge: strings.Repeat("d", 64)}
	if operation != "CreateExecution" && operation != "PrepareImage" {
		request.ResourceID = strings.Repeat("c", 64)
	}
	request.OperationID = request.OperationIdentity()
	b := testBinding()
	b.ExecutionID = spec.ExecutionId
	b.Generation = spec.Generation
	b.AttemptID = spec.AttemptId
	b.SpecHash = spec.SpecHash
	grant := SignedExecutionGrant{Grant: ExecutionGrant{Version: ExecutionGrantVersion, Audience: "neticora-broker:" + b.InstallationID, Operation: operation, OperationID: request.OperationID, ExpectedRevision: "0", ExpectedState: executionState(operation), ResourceID: request.ResourceID, Challenge: request.Challenge, Binding: b, Spec: spec, NotBefore: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(15 * time.Second).Format(time.RFC3339Nano)}}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signExecution(t, &grant, private)
	return request, grant, public, private, now
}

func signExecution(t *testing.T, s *SignedExecutionGrant, key ed25519.PrivateKey) {
	t.Helper()
	raw, err := canonical(s.Grant)
	if err != nil {
		t.Fatal(err)
	}
	s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(executionGrantDomain), raw...)))
}

func TestExecutionGrantScopeAndSubstitution(t *testing.T) {
	for _, action := range []string{"PrepareImage", "CreateExecution", "StartExecution", "StopExecution", "RemoveExecution"} {
		t.Run(action, func(t *testing.T) {
			r, s, key, _, now := executionFixture(t, action)
			if err := VerifyExecutionGrant(s, r, key, testBinding(), now); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, name := range []string{"forged", "expired", "wrong-operation", "image", "profile", "generation", "attempt", "revision", "challenge", "resource", "state", "issuer", "status-domain"} {
		t.Run(name, func(t *testing.T) {
			r, s, key, private, now := executionFixture(t, "StartExecution")
			switch name {
			case "forged":
				s.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
			case "expired":
				now = now.Add(15 * time.Second)
			case "wrong-operation":
				r.Operation = "CreateExecution"
			case "image":
				s.Grant.Spec.ImageDigest = "sha256:" + strings.Repeat("e", 64)
				signExecution(t, &s, private)
			case "profile":
				s.Grant.Spec.IsolationProfile = "isolated"
				signExecution(t, &s, private)
			case "generation":
				s.Grant.Binding.Generation = "99"
				signExecution(t, &s, private)
			case "attempt":
				s.Grant.Binding.AttemptID = "other"
				signExecution(t, &s, private)
			case "revision":
				r.ExpectedRevision = "1"
			case "challenge":
				r.Challenge = strings.Repeat("e", 64)
			case "resource":
				r.ResourceID = strings.Repeat("e", 64)
			case "state":
				s.Grant.ExpectedState = "CLEANED"
				signExecution(t, &s, private)
			case "issuer":
				key, _, _ = ed25519.GenerateKey(rand.Reader)
			case "status-domain":
				raw, _ := canonical(s.Grant)
				s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte("neticora-runnerd-broker-grant-v1\n"), raw...)))
			}
			if VerifyExecutionGrant(s, r, key, testBinding(), now) == nil {
				t.Fatal("invalid execution authority accepted")
			}
		})
	}
}

func TestPlatformIssuedExecutionGrantInterop(t *testing.T) {
	raw, err := os.ReadFile("testdata/platform-execution-grant.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Request   ExecutionGrantRequest `json:"request"`
		Signed    SignedExecutionGrant  `json:"signed"`
		PublicKey string                `json:"publicKey"`
		Now       string                `json:"now"`
	}
	if err = decode(raw, &vector); err != nil {
		t.Fatal(err)
	}
	key, err := base64.StdEncoding.DecodeString(vector.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, vector.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyExecutionGrant(vector.Signed, vector.Request, key, vector.Signed.Grant.Binding, now); err != nil {
		t.Fatal("TypeScript-issued grant rejected:", err)
	}
	vector.Signed.Grant.Spec.ImageDigest = "sha256:" + strings.Repeat("e", 64)
	if VerifyExecutionGrant(vector.Signed, vector.Request, key, vector.Signed.Grant.Binding, now) == nil {
		t.Fatal("modified platform grant accepted")
	}
}

func TestPlatformCommitCertificateInterop(t *testing.T) {
	raw, err := os.ReadFile("testdata/platform-commit.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Request     ExecutionGrantRequest `json:"request"`
		Grant       SignedExecutionGrant  `json:"grant"`
		Certificate SignedCommit          `json:"certificate"`
		PublicKey   string                `json:"publicKey"`
		Now         string                `json:"now"`
	}
	if err = decode(raw, &v); err != nil {
		t.Fatal(err)
	}
	key, err := base64.StdEncoding.DecodeString(v.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, v.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyExecutionGrant(v.Grant, v.Request, key, v.Grant.Grant.Binding, now); err != nil {
		t.Fatal(err)
	}
	if err = verifyCommit(v.Certificate, v.Grant, key, now); err != nil {
		t.Fatal("TypeScript platform commit rejected:", err)
	}
	v.Certificate.Commit.Challenge = strings.Repeat("e", 64)
	if verifyCommit(v.Certificate, v.Grant, key, now) == nil {
		t.Fatal("substituted commit accepted")
	}
}
