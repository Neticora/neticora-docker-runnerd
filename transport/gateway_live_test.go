package transport_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/identity"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

// Explicitly opt in with a disposable enrollment token. Retain the protected
// state directory until the test host is revoked, including after a failed run.
// This tests SDK interoperability, not daemon persistence or execution admission.
func TestLiveGatewayEnrollment(t *testing.T) {
	endpoint := os.Getenv("RUNNERD04_LIVE_ENDPOINT")
	if endpoint == "" {
		t.Skip("set RUNNERD04_LIVE_ENDPOINT for explicit live qualification")
	}
	tokenFile := os.Getenv("RUNNERD04_ENROLLMENT_TOKEN_FILE")
	stateDir := os.Getenv("RUNNERD04_LIVE_STATE_DIR")
	expectedTenant := os.Getenv("RUNNERD04_EXPECTED_TENANT_ID")
	if tokenFile == "" || stateDir == "" || expectedTenant == "" {
		t.Fatal("token file, canonical expected tenant ID and a new protected state directory are required")
	}
	client, err := transport.New(endpoint, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := createLiveState(stateDir); err != nil {
		t.Fatal("state directory must be new and protected:", err)
	}
	lockLiveState(t)
	write := func(name string, data []byte) { t.Helper(); liveWrite(t, name, data) }

	nonce := func() string {
		t.Helper()
		var bytes [24]byte
		if _, err := rand.Read(bytes[:]); err != nil {
			t.Fatal("cannot generate nonce")
		}
		return hex.EncodeToString(bytes[:])
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("cannot generate test key")
	}
	requestID, bootID := nonce(), nonce()
	write("private-key.seed", private.Seed())
	write("request-id", []byte(requestID))
	write("boot-id", []byte(bootID))
	write("endpoint", []byte(endpoint))
	rawToken, err := hostfs.ReadPrivate(tokenFile, 16384)
	if err != nil {
		t.Fatal("cannot read enrollment token file")
	}
	enrollment, err := identity.Enrollment(private, requestID, strings.TrimSpace(string(rawToken)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	raw, err := client.Post(ctx, "/enroll", "", enrollment, "EnrollmentResponse")
	if err != nil {
		t.Fatal("enrollment failed; retain protected state for identical-request recovery")
	}
	write("enrollment.json", raw)
	var enrolled protocol.EnrollmentResponse
	if err := json.Unmarshal(raw, &enrolled); err != nil {
		t.Fatal(err)
	}
	t.Logf("test host registered: %s; revoke after qualification", enrolled.Identity.HostId)
	recovered, err := client.Post(ctx, "/enroll", "", enrollment, "EnrollmentResponse")
	if err != nil || string(recovered) != string(raw) {
		t.Fatal("identical enrollment response recovery failed")
	}
	for round := 0; round < 2; round++ {
		assertion, err := identity.Assertion(private, enrolled.Identity, bootID, nonce(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		raw, err := client.Post(ctx, "/token", "", assertion, "TokenResponse")
		if err != nil {
			t.Fatal("signed token exchange failed")
		}
		var access protocol.TokenResponse
		if err := json.Unmarshal(raw, &access); err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+"/token", bytes.NewReader(assertion.Bytes()))
		if err != nil {
			t.Fatal("cannot construct replay check")
		}
		request.Header.Set("Content-Type", "application/json")
		replayClient := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		replay, err := replayClient.Do(request)
		if err != nil {
			t.Fatal("replay check transport failed")
		}
		replay.Body.Close()
		if replay.StatusCode != http.StatusUnauthorized {
			t.Fatalf("replay check: expected 401, received %d", replay.StatusCode)
		}
		config, err := client.Config(ctx, access.AccessToken)
		if err != nil {
			t.Fatal("authenticated configuration failed")
		}
		var response protocol.ConfigResponse
		if err := json.Unmarshal(config, &response); err != nil {
			t.Fatal(err)
		}
		if response.AdmissionEnabled {
			t.Fatal("live qualification must not enable execution admission")
		}
	}
	marker, err := json.Marshal(disposableHost{Purpose: disposablePurpose, Endpoint: strings.TrimRight(endpoint, "/"), HostID: enrolled.Identity.HostId, TenantID: expectedTenant, RequestID: requestID})
	if err != nil {
		t.Fatal(err)
	}
	write("disposable-host.json", marker)

}
