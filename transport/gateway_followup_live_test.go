package transport_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/identity"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

type liveIdentity struct {
	Identity protocol.HostIdentity `json:"identity"`
	Seed     []byte                `json:"seed"`
}

func liveRead(t *testing.T, name string) []byte {
	t.Helper()
	data, err := readLiveState(os.Getenv("RUNNERD04_LIVE_STATE_DIR"), name)
	if err != nil {
		t.Fatal("protected live-test state unavailable:", name)
	}
	return data
}

func liveWrite(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := writeLiveState(os.Getenv("RUNNERD04_LIVE_STATE_DIR"), name, data); err != nil {
		t.Fatal("protected live-test state write rejected:", err)
	}
}

func liveNonce(t *testing.T) string {
	t.Helper()
	var value [24]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal("nonce generation failed")
	}
	return hex.EncodeToString(value[:])
}

func liveClient(t *testing.T) (*transport.Client, string) {
	t.Helper()
	endpoint := os.Getenv("RUNNERD04_LIVE_ENDPOINT")
	if endpoint == "" {
		t.Skip("explicit live endpoint required")
	}
	if os.Getenv("RUNNERD04_LIVE_STATE_DIR") == "" {
		t.Fatal("protected existing identity directory required")
	}
	lockLiveState(t)
	client, err := transport.New(endpoint, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client, strings.TrimRight(endpoint, "/")
}

// Do not log raw responses: token exchanges contain live credentials.
func liveHTTP(t *testing.T, method, url, token string, body []byte, headers map[string]string) (int, []byte, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal("cannot construct live probe")
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	res, err := client.Do(req)
	if err != nil {
		t.Fatal("live HTTP probe failed")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, protocol.MaxWireBytes+1))
	if err != nil || len(raw) > protocol.MaxWireBytes {
		t.Fatal("unreadable or oversized live response")
	}
	return res.StatusCode, raw, res.Header
}

func liveToken(t *testing.T, client *transport.Client, key ed25519.PrivateKey, host protocol.HostIdentity) string {
	t.Helper()
	assertion, err := identity.Assertion(key, host, string(liveRead(t, "boot-id")), liveNonce(t), time.Now())
	if err != nil {
		t.Fatal("cannot sign live assertion")
	}
	raw, err := client.Post(context.Background(), "/token", "", assertion, "TokenResponse")
	if err != nil {
		t.Fatal("live assertion exchange rejected")
	}
	var response protocol.TokenResponse
	if json.Unmarshal(raw, &response) != nil {
		t.Fatal("invalid token response")
	}
	return response.AccessToken
}

func liveProblem(t *testing.T, status int, raw []byte, expected int) {
	t.Helper()
	if status != expected {
		t.Fatalf("expected HTTP %d, received %d", expected, status)
	}
	if protocol.ValidateInboundJSON("Problem", raw) != nil {
		t.Fatal("rejection was not a valid host Problem")
	}
}

// Uses an already enrolled disposable host; never performs runtime execution.
// The capability payload deliberately claims zero capacity and no accepted
// profile. It is synthetic protocol evidence, not an engine availability probe.
func TestLiveGatewayHeartbeatRotation(t *testing.T) {
	client, endpoint := liveClient(t)
	if err := ensureFreshRotation(os.Getenv("RUNNERD04_LIVE_STATE_DIR")); err != nil {
		t.Fatal(err)
	}
	var enrolled protocol.EnrollmentResponse
	if json.Unmarshal(liveRead(t, "enrollment.json"), &enrolled) != nil {
		t.Fatal("invalid retained enrollment")
	}
	seed := liveRead(t, "private-key.seed")
	if len(seed) != ed25519.SeedSize {
		t.Fatal("invalid private key seed")
	}
	requireDisposableLiveHost(t, endpoint, enrolled.Identity)
	key := ed25519.NewKeyFromSeed(seed)
	access := liveToken(t, client, key, enrolled.Identity)
	status, raw, headers := liveHTTP(t, "GET", endpoint+"/me/config", access, nil, nil)
	if status != 200 || protocol.ValidateInboundJSON("ConfigResponse", raw) != nil {
		t.Fatal("live config unavailable")
	}
	var config protocol.ConfigResponse
	if json.Unmarshal(raw, &config) != nil || config.AdmissionEnabled {
		t.Fatal("qualification requires admission off")
	}
	etag := headers.Get("ETag")
	if etag == "" {
		t.Fatal("config ETag absent")
	}
	status, _, _ = liveHTTP(t, "GET", endpoint+"/me/config", access, nil, map[string]string{"If-None-Match": etag})
	if status != 304 {
		t.Fatalf("expected ETag 304, received %d", status)
	}
	platform := map[string]any{"os": runtime.GOOS, "architecture": runtime.GOARCH, "build": "qualification-no-runtime-probed"}
	payload := map[string]any{
		"identity": enrolled.Identity, "agentVersion": "runnerd04-sdk-qualification", "protocolVersion": "1.0.0",
		"inventoryGeneration": "1", "effectivePolicyGeneration": config.Policy.Generation,
		"capabilities": map[string]any{"host": platform, "engine": platform, "endpointIdentity": "qualification-unprobed",
			"runtimeVersion": "unprobed", "runtimeMechanism": "unprobed", "configurationGeneration": "1", "probeGeneration": "1",
			"observedAt": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), "profiles": []string{}, "dockerBuild": false, "hardStorageLimit": false,
			"capacity": map[string]string{"cpuMillis": "0", "memoryBytes": "0", "storageBytes": "0", "slots": "0"}, "supportedImageFamilies": []string{}},
	}
	heartbeat, err := protocol.EncodeValidated("HostHeartbeat", payload)
	if err != nil {
		t.Fatal("invalid qualification heartbeat")
	}
	raw, err = client.Post(context.Background(), "/me/heartbeat", access, heartbeat, "ConfigResponse")
	if err != nil {
		t.Fatal("heartbeat rejected")
	}
	if json.Unmarshal(raw, &config) != nil || config.AdmissionEnabled {
		t.Fatal("heartbeat granted admission")
	}
	payload["identity"] = protocol.HostIdentity{HostId: enrolled.Identity.HostId, KeyId: enrolled.Identity.KeyId, KeyVersion: enrolled.Identity.KeyVersion, SessionEpoch: "999999"}
	stale, err := protocol.EncodeValidated("HostHeartbeat", payload)
	if err != nil {
		t.Fatal(err)
	}
	status, raw, _ = liveHTTP(t, "POST", endpoint+"/me/heartbeat", access, stale.Bytes(), nil)
	liveProblem(t, status, raw, 401)
	_, next, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("new key generation failed")
	}
	if err := persistRotationAttempt(os.Getenv("RUNNERD04_LIVE_STATE_DIR"), liveRotationAttempt{Identity: enrolled.Identity, NextSeed: next.Seed(), RequestID: liveNonce(t)}); err != nil {
		t.Fatal(err)
	}
	rotation, _, err := reconstructRotation(os.Getenv("RUNNERD04_LIVE_STATE_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err = client.Post(context.Background(), "/me/keys/rotate", access, rotation, "EnrollmentResponse")
	if err != nil {
		t.Fatal("rotation outcome uncertain; retain both keys and request identity")
	}
	state, err := commitRotationResponse(os.Getenv("RUNNERD04_LIVE_STATE_DIR"), raw)
	if err != nil {
		t.Fatal(err)
	}
	rotated := protocol.EnrollmentResponse{Identity: state.Identity}
	recovered, err := client.Post(context.Background(), "/me/keys/rotate", access, rotation, "EnrollmentResponse")
	if err != nil || !bytes.Equal(raw, recovered) {
		t.Fatal("rotation response recovery failed")
	}
	status, raw, _ = liveHTTP(t, "GET", endpoint+"/me/config", access, nil, nil)
	liveProblem(t, status, raw, 401)
	oldAssertion, err := identity.Assertion(key, enrolled.Identity, string(liveRead(t, "boot-id")), liveNonce(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	status, raw, _ = liveHTTP(t, "POST", endpoint+"/token", "", oldAssertion.Bytes(), nil)
	liveProblem(t, status, raw, 401)
	fresh := liveToken(t, client, next, rotated.Identity)
	if _, err := client.Config(context.Background(), fresh); err != nil {
		t.Fatal("new identity configuration failed")
	}
	t.Log("PASS config ETag, zero-capacity heartbeat, stale epoch rejection, rotation/recovery, old-key/token fencing; host", rotated.Identity.HostId)
}

func TestLiveGatewayBodyAndHostLimits(t *testing.T) {
	client, endpoint := liveClient(t)
	var state liveIdentity
	if json.Unmarshal(liveRead(t, "rotated-state.json"), &state) != nil || len(state.Seed) != ed25519.SeedSize {
		t.Fatal("valid rotated identity required")
	}
	requireDisposableLiveHost(t, endpoint, state.Identity)
	for _, probe := range []struct {
		name     string
		body     []byte
		status   int
		encoding string
	}{
		{"duplicate field", []byte(`{"requestId":"a","requestId":"b"}`), 400, ""},
		{"unknown field", []byte(`{"unknown":true}`), 400, ""},
		{"invalid Unicode", []byte("{\"requestId\":\"\xff\"}"), 400, ""},
		{"oversized", bytes.Repeat([]byte(" "), 65537), 413, ""},
	} {
		t.Run(probe.name, func(t *testing.T) {
			status, raw, _ := liveHTTP(t, "POST", endpoint+"/enroll", "", probe.body, nil)
			liveProblem(t, status, raw, probe.status)
		})
	}
	var compressed bytes.Buffer
	zip := gzip.NewWriter(&compressed)
	if _, err := zip.Write([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if zip.Close() != nil {
		t.Fatal("gzip fixture failed")
	}
	status, raw, _ := liveHTTP(t, "POST", endpoint+"/enroll", "", compressed.Bytes(), map[string]string{"Content-Encoding": "gzip"})
	liveProblem(t, status, raw, 415)
	t.Log("waiting 61 seconds without host requests for a fresh exclusive test-host window")
	if err := waitFreshHostWindow(t.Context()); err != nil {
		t.Fatal(err)
	}
	access := liveToken(t, client, ed25519.NewKeyFromSeed(state.Seed), state.Identity)
	err := qualifyHostBoundary(func() (int, error) {
		status, raw, _ := liveHTTP(t, "GET", endpoint+"/me/config", access, nil, nil)
		if status == 200 {
			var config protocol.ConfigResponse
			if protocol.ValidateInboundJSON("ConfigResponse", raw) != nil || json.Unmarshal(raw, &config) != nil || config.AdmissionEnabled {
				return status, errors.New("rate probe requires validated admission-disabled config")
			}
		}
		if status == 429 {
			liveProblem(t, status, raw, 429)
		}
		return status, nil
	}, func() (int, error) {
		status, raw, _ := liveHTTP(t, "POST", endpoint+"/token", "", []byte(`{}`), nil)
		if status == 400 {
			liveProblem(t, status, raw, 400)
		}
		return status, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("PASS fresh-window host boundary: exactly 120 accepted, then 5 limited; anonymous/global control not limited")
}

// An operator must first hold a row lock on this disposable test host and then
// create deadline-lock-ready in the protected state directory. No production
// handler is modified or given a test-only timeout bypass.
func TestLiveGatewayDeadline(t *testing.T) {
	client, endpoint := liveClient(t)
	if os.Getenv("RUNNERD04_CONTROLLED_DEADLINE") != "true" {
		t.Skip("requires explicit coordination of a disposable host row lock")
	}
	var state liveIdentity
	if json.Unmarshal(liveRead(t, "rotated-state.json"), &state) != nil || len(state.Seed) != ed25519.SeedSize {
		t.Fatal("valid rotated identity required")
	}
	requireDisposableLiveHost(t, endpoint, state.Identity)
	access := liveToken(t, client, ed25519.NewKeyFromSeed(state.Seed), state.Identity)
	liveWrite(t, "deadline-client-ready", []byte("ready"))
	t.Log("deadline client ready; awaiting disposable host lock")
	until := time.Now().Add(45 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(os.Getenv("RUNNERD04_LIVE_STATE_DIR"), "deadline-lock-ready")); err == nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal("operator did not establish the test-host lock")
		}
		time.Sleep(100 * time.Millisecond)
	}
	started := time.Now()
	status, raw, _ := liveHTTP(t, "GET", endpoint+"/me/config", access, nil, nil)
	elapsed := time.Since(started)
	liveProblem(t, status, raw, 408)
	if elapsed < 7*time.Second || elapsed >= 10*time.Second {
		t.Fatalf("structured deadline arrived outside application/backend margin: %v", elapsed)
	}
	t.Logf("PASS structured application 408 through live Cloudflare/Gateway in %v", elapsed.Round(time.Millisecond))
}

// Requires a real authorized administrator session. No actor impersonation or
// direct database writes are used to simulate administrative acceptance.
func TestLiveGatewayRevocation(t *testing.T) {
	client, endpoint := liveClient(t)
	file := os.Getenv("RUNNERD04_ADMIN_HEADER_FILE")
	tenant := os.Getenv("RUNNERD04_EXPECTED_TENANT_ID")
	if file == "" || tenant == "" {
		t.Skip("genuine administrator header file and canonical expected tenant ID required")
	}
	root := strings.TrimSuffix(endpoint, "/runner-hosts")
	management := root + "/tenants/" + url.PathEscape(tenant) + "/runner-hosts"
	var state liveIdentity
	if json.Unmarshal(liveRead(t, "rotated-state.json"), &state) != nil || len(state.Seed) != ed25519.SeedSize {
		t.Fatal("valid rotated identity required")
	}
	headers := requireDisposableLiveHost(t, endpoint, state.Identity)
	key := ed25519.NewKeyFromSeed(state.Seed)
	access := liveToken(t, client, key, state.Identity)
	status, _, _ := liveHTTP(t, "GET", management, "", nil, nil)
	if status != 401 {
		t.Fatalf("unauthenticated management expected 401, received %d", status)
	}
	status, raw, _ := liveHTTP(t, "GET", management+"/"+state.Identity.HostId, "", nil, headers)
	if status != 200 {
		t.Fatalf("administrator host lookup expected 200, received %d", status)
	}
	status, _, _ = liveHTTP(t, "GET", root+"/tenants/neticora-admin/runner-hosts/"+state.Identity.HostId, "", nil, headers)
	if status != 404 {
		t.Fatalf("cross-tenant host lookup expected 404, received %d", status)
	}
	status, raw, _ = liveHTTP(t, "POST", management+"/enrollment-tokens", "", []byte(`{}`), headers)
	if status != 201 {
		t.Fatalf("administrator enrollment creation expected 201, received %d", status)
	}
	var enrollment struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if json.Unmarshal(raw, &enrollment) != nil || enrollment.ID == "" || enrollment.Token == "" {
		t.Fatal("invalid administrative enrollment result")
	}
	status, raw, _ = liveHTTP(t, "GET", management+"/enrollment-tokens", "", nil, headers)
	if status != 200 {
		t.Fatal("enrollment metadata unavailable")
	}
	var metadata []map[string]json.RawMessage
	if json.Unmarshal(raw, &metadata) != nil {
		t.Fatal("invalid enrollment metadata")
	}
	for _, entry := range metadata {
		if _, ok := entry["token"]; ok {
			t.Fatal("metadata exposed token")
		}
		if _, ok := entry["tokenHash"]; ok {
			t.Fatal("metadata exposed token hash")
		}
	}
	status, _, _ = liveHTTP(t, "POST", management+"/enrollment-tokens/"+enrollment.ID+"/revoke", "", []byte(`{}`), headers)
	if status != 201 {
		t.Fatalf("enrollment revocation expected 201, received %d", status)
	}
	_, ephemeral, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.Enrollment(ephemeral, liveNonce(t), enrollment.Token)
	if err != nil {
		t.Fatal(err)
	}
	status, raw, _ = liveHTTP(t, "POST", endpoint+"/enroll", "", proof.Bytes(), nil)
	liveProblem(t, status, raw, 401)
	status, _, _ = liveHTTP(t, "POST", management+"/"+state.Identity.HostId+"/keys/"+state.Identity.KeyId+"/revoke", "", []byte(`{}`), headers)
	if status != 201 {
		t.Fatalf("key revocation expected 201, received %d", status)
	}
	status, raw, _ = liveHTTP(t, "GET", endpoint+"/me/config", access, nil, nil)
	liveProblem(t, status, raw, 401)
	assertion, err := identity.Assertion(key, state.Identity, string(liveRead(t, "boot-id")), liveNonce(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	status, raw, _ = liveHTTP(t, "POST", endpoint+"/token", "", assertion.Bytes(), nil)
	liveProblem(t, status, raw, 401)
	status, _, _ = liveHTTP(t, "POST", management+"/"+state.Identity.HostId+"/actions", "", []byte(`{"action":"revoke","reason":"Runnerd 04 live qualification completed"}`), headers)
	if status != 201 {
		t.Fatalf("host revocation expected 201, received %d", status)
	}
	status, raw, _ = liveHTTP(t, "GET", endpoint+"/me/config", access, nil, nil)
	liveProblem(t, status, raw, 401)
	t.Log("PASS administrative tenant scope, enrollment metadata/revocation, key revocation, cached-token rejection and host revocation; host", state.Identity.HostId)
	liveWrite(t, "revocation-completed", []byte(state.Identity.HostId))
}
