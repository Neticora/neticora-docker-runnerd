//go:build linux && runnerd_qualification

package qualfixture_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/identity"
	"github.com/Neticora/neticora-docker-runnerd/internal/qualfixture"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

type fixture struct {
	config qualfixture.Config
	key    ed25519.PrivateKey
	server *qualfixture.Server
	http   *httptest.Server
	client *transport.Client
	state  string
	raw    []byte
	start  json.RawMessage
}

func setup(t *testing.T) *fixture {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	name := "runnerd09-lab-fixture"
	start := storetest.Object(t, storetest.Start(t, "fixture"))
	spec := start["spec"].(map[string]any)
	spec["poolId"] = name
	spec["isolationProfile"] = "isolated"
	spec["dockerBuild"] = true
	spec["templateVersion"] = "linux-github-kata-v2"
	spec["profileVersion"] = "docker-kata-rs-qemu-v3-" + strings.Repeat("a", 64)
	encoded := storetest.Encode(t, "HostCommand", start)
	var command protocol.StartCommand
	json.Unmarshal(encoded, &command)
	cleanupRaw := storetest.Encode(t, "HostCommand", map[string]any{"kind": "cleanup", "commandId": "cleanup-fixture", "executionId": command.Spec.ExecutionId, "generation": "1"})
	var cleanup protocol.ControlCommand
	json.Unmarshal(cleanupRaw, &cleanup)
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	bootstrap := filepath.Join(dir, "bootstrap")
	os.WriteFile(bootstrap, []byte("fixture-bootstrap-not-production"), 0600)
	c := qualfixture.Config{Version: "runnerd09-control-fixture-v1", CaseID: "fixture", Identity: protocol.HostIdentity{HostId: name, KeyId: "lab-key", KeyVersion: "1", SessionEpoch: "1"}, BootID: "lab-fixture-boot-0123456789", EndpointIdentity: "engine-a", HostPublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), Start: command, Cleanup: cleanup, Policy: protocol.LocalPolicy{Generation: "1", AllowedProfiles: []string{command.Spec.ProfileVersion}, AllowedTrustClasses: []protocol.LocalPolicyAllowedTrustClasses{"trusted"}, Limits: command.Spec.Resources}, BootstrapFile: bootstrap, BootstrapExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}
	raw, _ := json.Marshal(c)
	server, err := qualfixture.New(raw, dir)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewTLSServer(server)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: httpServer.Certificate().Raw})
	client, err := transport.NewWithRoots(httpServer.URL+"/api/v1/runner-hosts", 5*time.Second, cert)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{c, key, server, httpServer, client, dir, raw, encoded}
	t.Cleanup(func() { client.Close(); httpServer.Close(); server.Close() })
	return f
}
func (f *fixture) token(t *testing.T) string {
	t.Helper()
	message, err := identity.Assertion(f.key, f.config.Identity, f.config.BootID, strings.Repeat("n", 16)+time.Now().Format("150405000000000"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.client.Post(context.Background(), "/token", "", message, "TokenResponse")
	if err != nil {
		t.Fatal(err)
	}
	token, err := protocol.DecodeTokenResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return token.AccessToken
}
func TestFixtureAuthenticatesAndRejectsReplayAndPlainHTTP(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	message, _ := identity.Assertion(f.key, f.config.Identity, f.config.BootID, strings.Repeat("q", 32), time.Now())
	if _, err := f.client.Post(ctx, "/token", "", message, "TokenResponse"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.Post(ctx, "/token", "", message, "TokenResponse"); err == nil {
		t.Fatal("assertion replay accepted")
	}
	if _, err := f.client.Config(ctx, "wrong-token"); err == nil {
		t.Fatal("unauthenticated configuration accepted")
	}
	token := f.token(t)
	if _, err := f.client.Config(ctx, token); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	f.server.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/runner-hosts/me/config", nil))
	if w.Code != 403 {
		t.Fatal("plaintext fixture accepted")
	}
}
func TestFixtureSealedStartIsDurablyIdempotent(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	token := f.token(t)
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	request := protocol.StartRequest{CommandId: f.config.Start.CommandId, ExecutionId: f.config.Start.Spec.ExecutionId, AttemptId: f.config.Start.Spec.AttemptId, Generation: "1", PolicyGeneration: "1", SpecHash: f.config.Start.Spec.SpecHash, StartRequestId: "request-fixture", BootstrapPublicKey: &pub}
	message, err := protocol.EncodeValidated("StartRequest", request)
	if err != nil {
		t.Fatal(err)
	}
	first, err := f.client.Post(ctx, "/me/start", token, message, "StartResponse")
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.client.Post(ctx, "/me/start", token, message, "StartResponse")
	if err != nil || string(first) != string(second) {
		t.Fatal("lost issuance response reminted bootstrap", err)
	}
	response, _ := protocol.DecodeStartResponse(first)
	plain, err := transport.OpenBootstrap(response.EncryptedBootstrap.MustGet(), key, transport.BootstrapBinding{TenantID: f.config.Identity.HostId, HostID: f.config.Identity.HostId, ExecutionID: request.ExecutionId, Generation: "1", StartRequestID: request.StartRequestId, SpecHash: request.SpecHash, ExpiresAt: *response.RecoveryExpiresAt}, time.Now())
	if err != nil || string(plain) != "fixture-bootstrap-not-production" {
		t.Fatal("sealed delivery mismatch", err)
	}
	request.StartRequestId = "another-request"
	changed, _ := protocol.EncodeValidated("StartRequest", request)
	if _, err = f.client.Post(ctx, "/me/start", token, changed, "StartResponse"); err == nil {
		t.Fatal("different issuance scope reused")
	}
}
func eventBatch(t *testing.T, f *fixture, seq uint64, state string) protocol.Outbound {
	raw := storetest.Event(t, f.start, seq, state)
	var event protocol.HostEvent
	json.Unmarshal(raw, &event)
	message, err := protocol.EncodeValidated("EventBatch", protocol.EventBatch{Events: []protocol.HostEvent{event}})
	if err != nil {
		t.Fatal(err)
	}
	return message
}
func TestFixtureRequiresCleanupAuthorityAndAbsenceBeforeRelease(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	token := f.token(t)
	if _, err := f.client.Events(ctx, token, eventBatch(t, f, 1, "cleaned")); err == nil {
		t.Fatal("premature release accepted")
	}
	if f.server.Snapshot().ReservationReleased {
		t.Fatal("failed event changed reservation")
	}
	if _, err := f.client.Events(ctx, token, eventBatch(t, f, 1, "cleanup-pending")); err != nil {
		t.Fatal(err)
	}
	rows, err := f.client.Commands(ctx, token)
	if err != nil || len(rows) != 2 {
		t.Fatal("cleanup not discoverable", err)
	}
	ack, _ := protocol.EncodeValidated("CommandAck", map[string]any{"commandId": f.config.Cleanup.CommandId, "payloadHash": f.config.Cleanup.PayloadHash, "generation": "1", "acceptance": "durable"})
	if err = f.client.AckCommand(ctx, token, ack); err != nil {
		t.Fatal(err)
	}
	if _, err = f.client.Events(ctx, token, eventBatch(t, f, 2, "cleaned")); err == nil {
		t.Fatal("stale initial absence released reservation")
	}
	inventory, _ := protocol.EncodeValidated("InventorySnapshot", map[string]any{"inventoryGeneration": "1", "endpointIdentity": f.config.EndpointIdentity, "complete": true, "observedAt": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), "resources": []any{}})
	if err = f.client.Inventory(ctx, token, inventory); err != nil {
		t.Fatal(err)
	}
	cleaned := eventBatch(t, f, 2, "cleaned")
	if _, err = f.client.Events(ctx, token, cleaned); err != nil {
		t.Fatal(err)
	}
	if !f.server.Snapshot().ReservationReleased {
		t.Fatal("completed disposal not reflected")
	}
	if _, err = f.client.Events(ctx, token, cleaned); err != nil {
		t.Fatal("duplicate event rejected", err)
	}
	if _, err = f.client.Events(ctx, token, eventBatch(t, f, 2, "exited")); err == nil {
		t.Fatal("conflicting event replay accepted")
	}
	if duplicate, err := qualfixture.New(f.raw, f.state); err == nil {
		duplicate.Close()
		t.Fatal("concurrent fixture writer accepted")
	}
	f.http.Close()
	f.server.Close()
	reopened, err := qualfixture.New(f.raw, f.state)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !reopened.Snapshot().ReservationReleased || reopened.Snapshot().Sequence != "2" {
		t.Fatal("durable fixture watermark lost")
	}
}
