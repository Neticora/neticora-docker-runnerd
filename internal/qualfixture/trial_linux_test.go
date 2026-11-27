//go:build linux && runnerd_qualification

package qualfixture_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/identity"
	"github.com/Neticora/neticora-docker-runnerd/internal/qualfixture"
)

func TestTrialKeepsHostIdentityAndInventoryButNeverReusesAttempt(t *testing.T) {
	f := setup(t)
	f.config.Start.Spec.AuthorizationExpiresAt = time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
	assertion, _ := identity.Assertion(f.key, f.config.Identity, f.config.BootID, strings.Repeat("r", 32), time.Now())
	if _, err := f.client.Post(context.Background(), "/token", "", assertion, "TokenResponse"); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	os.Chmod(parent, 0700)
	previous := filepath.Join(parent, "previous.json")
	var state qualfixture.State
	saved, _ := os.ReadFile(filepath.Join(f.state, "state.json"))
	json.Unmarshal(saved, &state)
	state.InventoryGeneration, state.Sequence, state.ReservationReleased = "740", "4", true
	raw, _ := json.Marshal(state)
	os.WriteFile(previous, raw, 0600)
	first, err := qualfixture.PrepareTrial(f.config, "one", f.config.BootstrapFile, f.config.BootstrapExpiresAt, previous, filepath.Join(parent, "one"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := qualfixture.PrepareTrial(f.config, "two", f.config.BootstrapFile, f.config.BootstrapExpiresAt, previous, filepath.Join(parent, "two"))
	if err != nil {
		t.Fatal(err)
	}
	if first.InitialInventoryGeneration != "740" || first.PreviousStateHash == "" || first.Identity != f.config.Identity || first.BootID != f.config.BootID || first.Start.Spec.ProfileVersion != f.config.Start.Spec.ProfileVersion || first.Start.Spec.ExecutionId == second.Start.Spec.ExecutionId || first.Start.Spec.AttemptId == second.Start.Spec.AttemptId || first.Start.Spec.SpecHash == second.Start.Spec.SpecHash || first.Start.PayloadHash == second.Start.PayloadHash {
		t.Fatal("trial reused identity or lost host continuity")
	}
	config, _ := json.Marshal(first)
	server, err := qualfixture.New(config, filepath.Join(parent, "one/state"))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if server.Snapshot().InventoryGeneration != "740" {
		t.Fatal("fixture reset durable inventory")
	}
	replay := httptest.NewRequest("POST", "/api/v1/runner-hosts/token", bytes.NewReader(assertion.Bytes()))
	replay.TLS = &tls.ConnectionState{}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, replay)
	if response.Code != 401 {
		t.Fatal("assertion nonce replay accepted across trial boundary")
	}
	spec, _ := json.Marshal(first.Start.Spec)
	hash, _ := protocol.PayloadHashJSON("ExecutionSpec", spec)
	if hash != first.Start.Spec.SpecHash {
		t.Fatal("trial spec hash stale")
	}
	if _, err = qualfixture.PrepareTrial(f.config, "one", f.config.BootstrapFile, f.config.BootstrapExpiresAt, previous, filepath.Join(parent, "one")); err == nil {
		t.Fatal("trial overwritten")
	}
	state.ReservationReleased = false
	raw, _ = json.Marshal(state)
	os.WriteFile(previous, raw, 0600)
	if _, err = qualfixture.PrepareTrial(f.config, "unresolved", f.config.BootstrapFile, f.config.BootstrapExpiresAt, previous, filepath.Join(parent, "unresolved")); err == nil {
		t.Fatal("new trial accepted unresolved prior reservation")
	}
}
