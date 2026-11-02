//go:build linux

package transport_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLiveStateProtection(t *testing.T) {
	dir := privateDir(t)
	if err := writeLiveState(dir, "seed", []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := writeLiveState(dir, "seed", []byte("replacement")); err != nil {
		t.Fatal(err)
	}
	data, err := readLiveState(dir, "seed")
	if err != nil || string(data) != "replacement" {
		t.Fatal("atomic replacement failed")
	}
	info, err := os.Stat(filepath.Join(dir, "seed"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe file permissions")
	}
	for _, name := range []string{"../outside", "/absolute", ".", "..", "nested/file", "nested\\file"} {
		if writeLiveState(dir, name, []byte("bad")) == nil {
			t.Fatal("unsafe filename accepted")
		}
	}
	if err := os.Chmod(filepath.Join(dir, "seed"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readLiveState(dir, "seed"); err == nil {
		t.Fatal("read accepted public secret")
	}
	if writeLiveState(dir, "seed", []byte("bad")) == nil {
		t.Fatal("write silently repaired public secret")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if writeLiveState(dir, "new", nil) == nil {
		t.Fatal("public identity directory accepted")
	}
	if _, err := readLiveState(dir, "seed"); err == nil {
		t.Fatal("public identity directory read accepted")
	}
}

func TestLiveStateRejectsSymlinksAndPlantedTemporaryFiles(t *testing.T) {
	dir := privateDir(t)
	outside := filepath.Join(privateDir(t), "outside")
	if err := os.WriteFile(outside, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := readLiveState(dir, "linked"); err == nil {
		t.Fatal("secret symlink read accepted")
	}
	if writeLiveState(dir, "linked", []byte("bad")) == nil {
		t.Fatal("destination symlink accepted")
	}
	link := filepath.Join(privateDir(t), "directory-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if writeLiveState(link, "new", nil) == nil {
		t.Fatal("symlink directory accepted")
	}
	if err := os.Symlink(outside, filepath.Join(dir, ".planted")); err != nil {
		t.Fatal(err)
	}
	if writeLiveStateWithName(dir, "new", []byte("bad"), func() (string, error) { return ".planted", nil }) == nil {
		t.Fatal("temporary symlink accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, ".existing"), []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	if writeLiveStateWithName(dir, "new", []byte("bad"), func() (string, error) { return ".existing", nil }) == nil {
		t.Fatal("existing temporary file truncated")
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "untouched" {
		t.Fatal("external target modified")
	}
	data, err = os.ReadFile(filepath.Join(dir, ".existing"))
	if err != nil || string(data) != "keep" {
		t.Fatal("planted temporary file modified")
	}
	if writeLiveStateWithName(dir, "new", nil, func() (string, error) { return "new", nil }) == nil {
		t.Fatal("temporary name equals destination")
	}
}

func TestLiveStateRejectsDifferentOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		info, err := os.Lstat("/root")
		if err != nil || info.Mode().Perm() != 0700 {
			t.Skip("a foreign-owned 0700 directory is needed to isolate the ownership check")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 {
			t.Skip("root-owned fixture unavailable")
		}
		// /root already has correct privacy bits: this must fail specifically
		// on ownership, before opening or writing anything inside it.
		if err := writeLiveState("/root", "never-written-by-test", nil); err == nil || !strings.Contains(err.Error(), "ownership") {
			t.Fatal("foreign-owned private directory did not fail ownership validation")
		}
		return
	}
	dir := privateDir(t)
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	defer os.Chown(dir, 0, 0)
	if writeLiveState(dir, "seed", nil) == nil {
		t.Fatal("foreign-owned state accepted")
	}
}

func TestDisposableHostGate(t *testing.T) {
	marker := disposableHost{Purpose: disposablePurpose, Endpoint: "https://example.test/api/v1/runner-hosts", HostID: "host-a", TenantID: "tenant-a", RequestID: "request-a"}
	host := protocol.HostIdentity{HostId: "host-a", KeyId: "key-a", KeyVersion: "1", SessionEpoch: "1"}
	for _, scenario := range []string{"valid", "no opt-in", "missing host", "missing tenant", "wrong host", "wrong tenant", "wrong endpoint", "wrong marker", "wrong request", "wrong identity"} {
		t.Run(scenario, func(t *testing.T) {
			m, h, endpoint, expectedHost, expectedTenant, request, opt := marker, host, marker.Endpoint, "host-a", "tenant-a", "request-a", true
			switch scenario {
			case "no opt-in":
				opt = false
			case "missing host":
				expectedHost = ""
			case "missing tenant":
				expectedTenant = ""
			case "wrong host":
				expectedHost = "host-b"
			case "wrong tenant":
				expectedTenant = "tenant-b"
			case "wrong endpoint":
				endpoint = "https://other.test"
			case "wrong marker":
				m.Purpose = "not-test"
			case "wrong request":
				request = "other"
			case "wrong identity":
				h.HostId = "other"
			}
			err := validateDisposable(m, h, endpoint, expectedHost, expectedTenant, request, opt)
			if (err == nil) != (scenario == "valid") {
				t.Fatal("unexpected disposable identity decision")
			}
		})
	}
}

func TestLiveHostDetailMustBeExplicitlySafe(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong tenant", "wrong host", "admission enabled", "missing admission", "not pending", "assigned", "missing authorizations"} {
		t.Run(scenario, func(t *testing.T) {
			host := map[string]any{"id": "host-a", "tenantId": "tenant-a", "admissionEnabled": false, "state": "PENDING", "authorizations": []string{}}
			switch scenario {
			case "wrong tenant":
				host["tenantId"] = "tenant-b"
			case "wrong host":
				host["id"] = "host-b"
			case "admission enabled":
				host["admissionEnabled"] = true
			case "missing admission":
				delete(host, "admissionEnabled")
			case "not pending":
				host["state"] = "READY"
			case "assigned":
				host["authorizations"] = []string{"pool"}
			case "missing authorizations":
				delete(host, "authorizations")
			}
			raw, err := json.Marshal(host)
			if err != nil {
				t.Fatal(err)
			}
			if (validateLiveHostDetail(raw, "host-a", "tenant-a") == nil) != (scenario == "valid") {
				t.Fatal("unsafe server host accepted")
			}
		})
	}
}

func TestHostBoundaryCannotPassOnUnrelatedThrottling(t *testing.T) {
	for _, scenario := range []string{"exact", "all limited", "early limit", "no limit", "global limited", "network failure"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			err := qualifyHostBoundary(func() (int, error) {
				calls++
				if scenario == "network failure" {
					return 0, errors.New("offline")
				}
				if scenario == "all limited" || (scenario == "early limit" && calls >= 120) {
					return 429, nil
				}
				if scenario == "no limit" || calls <= 120 {
					return 200, nil
				}
				return 429, nil
			}, func() (int, error) {
				if scenario == "global limited" {
					return 429, nil
				}
				return 400, nil
			})
			if (err == nil) != (scenario == "exact") {
				t.Fatal("incorrect host boundary accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitFreshHostWindow(ctx) == nil {
		t.Fatal("canceled fresh-window wait accepted")
	}
}

func TestRotationRecoveryReconstructsPersistedAttempt(t *testing.T) {
	dir := privateDir(t)
	_, old, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, next, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeLiveState(dir, "private-key.seed", old.Seed()); err != nil {
		t.Fatal(err)
	}
	attempt := liveRotationAttempt{Identity: protocol.HostIdentity{HostId: "host-a", KeyId: "key-a", KeyVersion: "1", SessionEpoch: "1"}, NextSeed: next.Seed(), RequestID: "rotation-request-a"}
	if err := persistRotationAttempt(dir, attempt); err != nil {
		t.Fatal(err)
	}
	first, _, err := reconstructRotation(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := reconstructRotation(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("persisted retry changed logical payload")
	}
	if persistRotationAttempt(dir, attempt) == nil {
		t.Fatal("existing uncertain rotation overwritten")
	}
	raw := []byte(`{"identity":{"hostId":"host-a","keyId":"key-b","keyVersion":"2","sessionEpoch":"2"},"protocol":{"version":"1.0.0","minimumRecoveryVersion":"1.0.0","minimumAdmissionVersion":"1.0.0"}}`)
	if _, err := commitRotationResponse(dir, bytes.Replace(raw, []byte("host-a"), []byte("host-b"), 1)); err == nil {
		t.Fatal("different host rotation response accepted")
	}
	state, err := commitRotationResponse(dir, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(state.Seed, next.Seed()) || state.Identity.KeyId != "key-b" {
		t.Fatal("recovered identity does not match next key")
	}
}

func TestFirstRotationResponseIsActuallyLost(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(`{"secret":"discarded-response"}`))
	}))
	defer server.Close()
	drop := &droppedRotationResponse{base: server.Client().Transport}
	client := &http.Client{Transport: drop}
	response, err := client.Post(server.URL+"/me/keys/rotate", "application/json", strings.NewReader(`{}`))
	if err == nil || response != nil || !drop.dropped || requests != 1 {
		t.Fatal("successful first response reached the caller or was retried")
	}
	response, err = client.Post(server.URL+"/me/keys/rotate", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || !bytes.Contains(data, []byte("discarded-response")) || requests != 2 {
		t.Fatal("explicit recovery response unavailable")
	}
}
