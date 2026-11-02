package transport_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

const disposablePurpose = "runnerd04-disposable-sdk-host-v1"

type disposableHost struct {
	Purpose   string `json:"purpose"`
	Endpoint  string `json:"endpoint"`
	HostID    string `json:"hostId"`
	TenantID  string `json:"tenantId"`
	RequestID string `json:"requestId"`
}

func createLiveState(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("invalid state directory")
	}
	if err := hostfs.CheckAncestors(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	root, err := hostfs.OpenState(dir)
	if err != nil {
		return err
	}
	return root.Close()
}

func stateName(name string) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") {
		return errors.New("invalid state filename")
	}
	return nil
}

func readLiveState(dir, name string) ([]byte, error) {
	if err := stateName(name); err != nil {
		return nil, err
	}
	root, err := hostfs.OpenState(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return hostfs.ReadPrivate(filepath.Join(dir, name), protocol.MaxWireBytes)
}

// A private, owner-checked directory and confined root protect both endpoints.
// Random exclusive temporary files cannot truncate a planted file/symlink.
// Existing destinations must themselves be protected regular files.
func writeLiveState(dir, name string, data []byte) error {
	return writeLiveStateWithName(dir, name, data, func() (string, error) {
		var value [16]byte
		if _, err := rand.Read(value[:]); err != nil {
			return "", err
		}
		return ".live-" + hex.EncodeToString(value[:]), nil
	})
}

func writeLiveStateWithName(dir, name string, data []byte, temporary func() (string, error)) error {
	if err := stateName(name); err != nil {
		return err
	}
	root, err := hostfs.OpenState(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Lstat(name); err == nil {
		if _, err = hostfs.ReadPrivate(filepath.Join(dir, name), protocol.MaxWireBytes); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := temporary()
	if err != nil {
		return err
	}
	if err := stateName(tmp); err != nil {
		return err
	}
	if tmp == name {
		return errors.New("temporary file must differ from destination")
	}
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("cannot exclusively create protected temporary file")
	}
	defer root.Remove(tmp)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return errors.New("cannot write protected state")
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = root.Rename(tmp, name); err != nil {
		return err
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validateDisposable(marker disposableHost, host protocol.HostIdentity, endpoint, expectedHost, expectedTenant, requestID string, enabled bool) error {
	if !enabled || expectedHost == "" || expectedTenant == "" {
		return errors.New("explicit destructive opt-in and expected host/tenant IDs required")
	}
	if marker.Purpose != disposablePurpose || marker.HostID != expectedHost || marker.TenantID != expectedTenant || host.HostId != expectedHost ||
		marker.Endpoint != strings.TrimRight(endpoint, "/") || marker.RequestID == "" || marker.RequestID != requestID {
		return errors.New("disposable enrollment marker or expected identity mismatch")
	}
	return nil
}

func validateLiveHostDetail(raw []byte, expectedHost, expectedTenant string) error {
	var host struct {
		ID             string             `json:"id"`
		TenantID       string             `json:"tenantId"`
		Admission      *bool              `json:"admissionEnabled"`
		State          string             `json:"state"`
		Authorizations *[]json.RawMessage `json:"authorizations"`
	}
	if json.Unmarshal(raw, &host) != nil || host.ID != expectedHost || host.TenantID != expectedTenant || host.Admission == nil || *host.Admission ||
		host.State != "PENDING" || host.Authorizations == nil || len(*host.Authorizations) != 0 {
		return errors.New("server host must match expected tenant/identity, be PENDING, admission-disabled and unassigned")
	}
	return nil
}

func liveAdminHeaders(t *testing.T) map[string]string {
	t.Helper()
	file := os.Getenv("RUNNERD04_ADMIN_HEADER_FILE")
	if file == "" {
		t.Fatal("protected administrator header file required for independent tenant verification")
	}
	header, err := hostfs.ReadPrivate(file, 16384)
	if err != nil {
		t.Fatal("administrator header ownership/permissions/type rejected")
	}
	name, value, ok := strings.Cut(strings.TrimSpace(string(header)), ":")
	value = strings.TrimSpace(value)
	if !ok || !strings.EqualFold(name, "Authorization") || !strings.HasPrefix(value, "Bearer ") || strings.ContainsAny(value, "\r\n") {
		t.Fatal("invalid administrator header format")
	}
	return map[string]string{"Authorization": value}
}

// Must run before exchanging host tokens or issuing any mutating HTTP request.
func requireDisposableLiveHost(t *testing.T, endpoint string, host protocol.HostIdentity) map[string]string {
	t.Helper()
	var marker disposableHost
	if json.Unmarshal(liveRead(t, "disposable-host.json"), &marker) != nil {
		t.Fatal("invalid disposable enrollment marker")
	}
	expectedHost, expectedTenant := os.Getenv("RUNNERD04_EXPECTED_HOST_ID"), os.Getenv("RUNNERD04_EXPECTED_TENANT_ID")
	if err := validateDisposable(marker, host, endpoint, expectedHost, expectedTenant, string(liveRead(t, "request-id")), os.Getenv("RUNNERD04_ALLOW_DESTRUCTIVE") == "true"); err != nil {
		t.Fatal(err)
	}
	headers := liveAdminHeaders(t)
	status, raw, _ := liveHTTP(t, "GET", strings.TrimSuffix(endpoint, "/runner-hosts")+"/tenants/"+url.PathEscape(expectedTenant)+"/runner-hosts/"+url.PathEscape(expectedHost), "", nil, headers)
	if status != 200 {
		t.Fatalf("independent disposable host lookup expected 200, received %d", status)
	}
	if err := validateLiveHostDetail(raw, expectedHost, expectedTenant); err != nil {
		t.Fatal(err)
	}
	return headers
}

func lockLiveState(t *testing.T) {
	t.Helper()
	root, err := hostfs.OpenState(os.Getenv("RUNNERD04_LIVE_STATE_DIR"))
	if err != nil {
		t.Fatal("unsafe live-test identity directory:", err)
	}
	lock, err := hostfs.Lock(root)
	if err != nil {
		root.Close()
		t.Fatal("another test owns this identity or state lock is unsafe")
	}
	t.Cleanup(func() { lock.Close(); root.Close() })
}

// Exact boundary, not merely "some 429". An already exhausted global bucket
// fails on request one. The final anonymous control must still pass the limiter.
func qualifyHostBoundary(request func() (int, error), control func() (int, error)) error {
	started := time.Now()
	for i := 0; i < 125; i++ {
		status, err := request()
		if err != nil {
			return err
		}
		expected := 200
		if i >= 120 {
			expected = 429
		}
		if status != expected {
			return fmt.Errorf("host boundary request %d: expected %d, received %d", i+1, expected, status)
		}
	}
	if time.Since(started) >= 55*time.Second {
		return errors.New("rate probe exceeded safe single-window duration")
	}
	status, err := control()
	if err != nil {
		return err
	}
	if status != 400 {
		return errors.New("anonymous/global control was limited or failed; host isolation unproven")
	}
	return nil
}

func waitFreshHostWindow(ctx context.Context) error {
	timer := time.NewTimer(61 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type droppedRotationResponse struct {
	base    http.RoundTripper
	dropped bool
}

func (d *droppedRotationResponse) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := d.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if !d.dropped && req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/me/keys/rotate") && res.StatusCode == 200 {
		size, copyErr := io.Copy(io.Discard, io.LimitReader(res.Body, protocol.MaxWireBytes+1))
		res.Body.Close()
		if copyErr != nil || size > protocol.MaxWireBytes {
			return nil, errors.New("rotation response discard failed")
		}
		d.dropped = true
		return nil, errors.New("rotation response deliberately lost before client delivery")
	}
	return res, nil
}
