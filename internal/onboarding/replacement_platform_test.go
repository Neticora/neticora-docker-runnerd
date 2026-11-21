//go:build linux && runnerd_enrollment_integration

package onboarding

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/identity"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

// TestPlatformEnrollmentReplacement uses the real Go setup/signing/HTTPS stack.
// The opt-in Node qualification driver supplies isolated TLS/platform fixtures on
// stdin. No credentials enter arguments, environment variables or diagnostics.
// Only the read-only Docker probe is stubbed; this is not runtime qualification.
func TestPlatformEnrollmentReplacement(t *testing.T) {
	if os.Getenv("RUNNERD_ENROLLMENT_PLATFORM_TEST") != "1" {
		t.Skip("explicit cross-language fixture required")
	}
	decoder := json.NewDecoder(os.Stdin)
	decoder.DisallowUnknownFields()
	var input struct {
		Endpoint string `json:"endpoint"`
		CA       string `json:"ca"`
		TenantID string `json:"tenantId"`
		PoolID   string `json:"poolId"`
		Token    string `json:"token"`
		Legacy   bool   `json:"legacy"`
		Original bool   `json:"original"`
	}
	if decoder.Decode(&input) != nil {
		t.Fatal("cannot read protected platform fixture")
	}
	nextToken := func() string {
		var message struct {
			Token string `json:"token"`
		}
		if decoder.Decode(&message) != nil {
			t.Fatal("platform fixture ended")
		}
		return message.Token
	}
	emit := func(phase string, values map[string]any) {
		if values == nil {
			values = map[string]any{}
		}
		values["phase"] = phase
		raw, _ := json.Marshal(values)
		fmt.Printf("RUNNERD_ENROLLMENT_EVENT %s\n", raw)
	}
	client, err := transport.NewWithRoots(input.Endpoint, 10*time.Second, []byte(input.CA))
	if err != nil {
		t.Fatal("cannot initialize fixture HTTPS transport")
	}
	defer client.Close()
	o, _ := fixture(t)
	o.PlatformURL = input.Endpoint
	o.TenantID = input.TenantID
	o.PoolID = input.PoolID
	current := input.Token
	o.Token = func() ([]byte, error) { return []byte(current), nil }
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if _, err := Setup(ctx, client, o); err == nil {
		t.Fatal("original fixture request unexpectedly completed")
	}
	original, err := os.ReadFile(filepath.Join(o.SetupDir, "attempt.json"))
	if err != nil {
		t.Fatal("original attempt not durable")
	}
	seed, err := os.ReadFile(filepath.Join(o.SetupDir, "original-key.seed"))
	if err != nil {
		t.Fatal("original key not durable")
	}
	defer clear(seed)
	var a attempt
	if readJSON(filepath.Join(o.SetupDir, "attempt.json"), &a) != nil {
		t.Fatal("cannot read original binding")
	}
	emit("original-retained", map[string]any{"requestId": a.RequestID, "fingerprint": a.Fingerprint})
	for _, phase := range []string{"candidate-retained", "typo-retained"} {
		current = nextToken()
		o.ReplaceToken = true
		if _, err := Setup(ctx, client, o); err == nil {
			t.Fatal("interrupted or invalid candidate registered")
		}
		emit(phase, nil)
	}
	current = nextToken()
	o.ReplaceToken = true
	if input.Legacy {
		// Reproduce an anchor-only client losing its successful response, while
		// retaining the same durable files the older client would have left behind.
		o.Checkpoint = func(point string) error {
			if point != "after-token-replacement" {
				return nil
			}
			key := ed25519.NewKeyFromSeed(seed)
			defer clear(key)
			message, err := identity.EnrollmentReplacing(key, a.RequestID, current, &protocol.EnrollmentTokenReplacement{TenantId: a.TenantID, RunnerDeploymentId: a.PoolID, PriorTokenHashes: []string{a.TokenHash}})
			if err != nil {
				return err
			}
			if _, err = client.Post(ctx, "/enroll", "", message, "EnrollmentResponse"); err == nil {
				return errors.New("legacy response was not lost")
			}
			return errors.New("legacy response lost")
		}
	}
	if _, err := Setup(ctx, client, o); err == nil {
		t.Fatal("response-loss fixture did not interrupt setup")
	}
	recoveryToken := current
	emit("response-lost", nil)
	later := nextToken()
	o.Checkpoint = nil
	if later != "" {
		current = later
		o.ReplaceToken = true
		if _, err := Setup(ctx, client, o); err == nil {
			t.Fatal("later candidate replaced an already registered identity")
		}
		emit("later-candidate-retained", nil)
		_ = nextToken()
	}
	current = recoveryToken
	if input.Original {
		current = input.Token
	}
	o.ReplaceToken = false
	binding, err := Setup(ctx, client, o)
	if err != nil {
		t.Fatal("original enrollment response could not be recovered")
	}
	after, err := os.ReadFile(filepath.Join(o.SetupDir, "attempt.json"))
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("original attempt changed")
	}
	afterSeed, err := os.ReadFile(filepath.Join(o.SetupDir, "original-key.seed"))
	defer clear(afterSeed)
	if err != nil || !bytes.Equal(seed, afterSeed) {
		t.Fatal("original key changed")
	}
	if binding.EnrollmentRequestID != a.RequestID || binding.PublicKeyFingerprint != a.Fingerprint {
		t.Fatal("platform changed original identity")
	}
	emit("completed", map[string]any{"hostId": binding.Identity.HostId, "installationId": binding.InstallationID, "requestId": a.RequestID, "fingerprint": a.Fingerprint, "originalStatePreserved": true})
}
