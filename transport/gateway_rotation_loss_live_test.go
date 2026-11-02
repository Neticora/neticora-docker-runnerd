package transport_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/identity"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

type liveRotationAttempt struct {
	Identity  protocol.HostIdentity `json:"identity"`
	NextSeed  []byte                `json:"nextSeed"`
	RequestID string                `json:"requestId"`
}

func ensureFreshRotation(dir string) error {
	root, err := hostfs.OpenState(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, name := range []string{"rotated-state.json", "rotation-attempt.json", "rotation-next.seed", "rotation-request-id"} {
		if _, err := root.Lstat(name); !os.IsNotExist(err) {
			return errors.New("rotation state already exists; inspect/recover instead of replacing keys")
		}
	}
	return nil
}

func persistRotationAttempt(dir string, attempt liveRotationAttempt) error {
	if err := ensureFreshRotation(dir); err != nil {
		return err
	}
	if len(attempt.NextSeed) != ed25519.SeedSize || attempt.RequestID == "" {
		return errors.New("invalid rotation attempt")
	}
	raw, err := json.Marshal(attempt)
	if err != nil {
		return err
	}
	return writeLiveState(dir, "rotation-attempt.json", raw)
}

func reconstructRotation(dir string) (protocol.Outbound, liveRotationAttempt, error) {
	var attempt liveRotationAttempt
	raw, err := readLiveState(dir, "rotation-attempt.json")
	if err != nil {
		return protocol.Outbound{}, attempt, err
	}
	if json.Unmarshal(raw, &attempt) != nil || len(attempt.NextSeed) != ed25519.SeedSize {
		return protocol.Outbound{}, attempt, errors.New("invalid retained rotation attempt")
	}
	seed, err := readLiveState(dir, "private-key.seed")
	if err != nil || len(seed) != ed25519.SeedSize {
		return protocol.Outbound{}, attempt, errors.New("original key unavailable")
	}
	wire, err := identity.Rotation(ed25519.NewKeyFromSeed(seed), ed25519.NewKeyFromSeed(attempt.NextSeed), attempt.Identity, attempt.RequestID)
	return wire, attempt, err
}

func commitRotationResponse(dir string, raw []byte) (liveIdentity, error) {
	var rotated protocol.EnrollmentResponse
	var state liveIdentity
	if protocol.ValidateInboundJSON("EnrollmentResponse", raw) != nil || json.Unmarshal(raw, &rotated) != nil {
		return state, errors.New("invalid rotation response")
	}
	_, attempt, err := reconstructRotation(dir)
	if err != nil {
		return state, err
	}
	version, err := strconv.ParseUint(attempt.Identity.KeyVersion, 10, 64)
	if err != nil {
		return state, err
	}
	epoch, err := strconv.ParseUint(attempt.Identity.SessionEpoch, 10, 64)
	if err != nil {
		return state, err
	}
	if version == ^uint64(0) || epoch == ^uint64(0) || rotated.Identity.HostId != attempt.Identity.HostId || rotated.Identity.KeyId == attempt.Identity.KeyId ||
		rotated.Identity.KeyVersion != strconv.FormatUint(version+1, 10) || rotated.Identity.SessionEpoch != strconv.FormatUint(epoch+1, 10) {
		return state, errors.New("rotation response changed host or did not advance key/session authority")
	}
	state = liveIdentity{Identity: rotated.Identity, Seed: attempt.NextSeed}
	encoded, err := json.Marshal(state)
	if err != nil {
		return state, err
	}
	return state, writeLiveState(dir, "rotated-state.json", encoded)
}

// Alternative to the ordinary rotation test, on its own newly enrolled host.
// The first successful response is drained and discarded by the transport before
// the caller sees it. Recovery reconstructs the request from persisted keys/ID.
// This does not claim daemon/process-restart recovery: the bounded old access
// token stays in memory, not in the persistent recovery bundle.
func TestLiveGatewayLostRotationResponse(t *testing.T) {
	client, endpoint := liveClient(t)
	if os.Getenv("RUNNERD04_LOSE_ROTATION_RESPONSE") != "true" {
		t.Skip("explicit lost-response scenario opt-in required")
	}
	dir := os.Getenv("RUNNERD04_LIVE_STATE_DIR")
	if err := ensureFreshRotation(dir); err != nil {
		t.Fatal(err)
	}
	var enrolled protocol.EnrollmentResponse
	if json.Unmarshal(liveRead(t, "enrollment.json"), &enrolled) != nil {
		t.Fatal("invalid enrollment identity")
	}
	requireDisposableLiveHost(t, endpoint, enrolled.Identity)
	seed := liveRead(t, "private-key.seed")
	if len(seed) != ed25519.SeedSize {
		t.Fatal("invalid original key")
	}
	access := liveToken(t, client, ed25519.NewKeyFromSeed(seed), enrolled.Identity)
	_, next, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistRotationAttempt(dir, liveRotationAttempt{Identity: enrolled.Identity, NextSeed: next.Seed(), RequestID: liveNonce(t)}); err != nil {
		t.Fatal(err)
	}
	wire, _, err := reconstructRotation(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(wire.Bytes())
	drop := &droppedRotationResponse{base: http.DefaultTransport}
	faultClient := &http.Client{Transport: drop, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if closer, ok := drop.base.(interface{ CloseIdleConnections() }); ok {
		defer closer.CloseIdleConnections()
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint+"/me/keys/rotate", bytes.NewReader(wire.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+access)
	if response, err := faultClient.Do(req); err == nil || !drop.dropped {
		if response != nil {
			response.Body.Close()
		}
		t.Fatal("first rotation response was not deliberately lost")
	}
	// No first response identity is available to the caller. Rebuild solely from
	// protected state, including the same request ID and both signing key seeds.
	wire, _, err = reconstructRotation(dir)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(wire.Bytes()) != want {
		t.Fatal("recovered rotation request changed")
	}
	recovered, err := client.Post(context.Background(), "/me/keys/rotate", access, wire, "EnrollmentResponse")
	if err != nil {
		t.Fatal("lost-response recovery failed; retain both keys/attempt for investigation")
	}
	state, err := commitRotationResponse(dir, recovered)
	if err != nil {
		t.Fatal(err)
	}
	status, raw, _ := liveHTTP(t, "GET", endpoint+"/me/config", access, nil, nil)
	liveProblem(t, status, raw, 401)
	fresh := liveToken(t, client, ed25519.NewKeyFromSeed(state.Seed), state.Identity)
	if _, err := client.Config(context.Background(), fresh); err != nil {
		t.Fatal("recovered key cannot authenticate")
	}
	t.Log("PASS deliberately lost rotation response recovered from persisted request/key state; host", state.Identity.HostId)
}
