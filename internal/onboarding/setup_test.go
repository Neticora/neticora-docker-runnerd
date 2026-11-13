package onboarding

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

type platform struct {
	binding        transport.InstallationBinding
	request        []byte
	effects, calls int
	lost           bool
	reject         bool
}

func (p *platform) Post(_ context.Context, path, _ string, m protocol.Outbound, _ string) ([]byte, error) {
	if p.reject {
		return nil, errors.New("request rejected")
	}
	if path == "/token" {
		return json.Marshal(map[string]string{"accessToken": strings.Repeat("a", 43), "expiresAt": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)})
	}
	p.calls++
	if len(p.request) > 0 && string(p.request) != string(m.Bytes()) {
		return nil, errors.New("attempt changed")
	}
	if len(p.request) == 0 {
		p.effects++
		p.request = m.Bytes()
		var r protocol.EnrollmentRequest
		_ = json.Unmarshal(p.request, &r)
		p.binding.EnrollmentRequestID = r.RequestId
		pub, _ := pem.Decode([]byte(r.PublicKey))
		sum := sha256.Sum256(pub.Bytes)
		p.binding.PublicKeyFingerprint = hex.EncodeToString(sum[:])
	}
	if p.lost {
		p.lost = false
		return nil, errors.New("response lost")
	}
	return json.Marshal(protocol.EnrollmentResponse{Identity: p.binding.Identity, Protocol: protocol.ProtocolCompatibility{Version: "1.0.0", MinimumAdmissionVersion: "1.0.0", MinimumRecoveryVersion: "1.0.0"}})
}
func (p *platform) Installation(context.Context, string) (transport.InstallationBinding, error) {
	return p.binding, nil
}
func fixture(t *testing.T) (Options, *platform) {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := hostfs.CheckAncestors(dir); e != nil {
		for path := dir; ; path = filepath.Dir(path) {
			info, _ := os.Stat(path)
			t.Logf("ancestor %s: %v", path, info)
			if path == "/" {
				break
			}
		}
		t.Fatal(e)
	}
	for _, d := range []string{"setup", "state", "etc"} {
		if e := os.Mkdir(filepath.Join(dir, d), 0700); e != nil {
			t.Fatal(e)
		}
	}
	o := Options{SetupDir: filepath.Join(dir, "setup"), StateDir: filepath.Join(dir, "state"), ConfigPath: filepath.Join(dir, "etc/config.json"), CredentialPath: filepath.Join(dir, "etc/identity.json"), PlatformURL: "https://control.test/runner-hosts", TenantID: "tenant-a", PoolID: "pool-a", RuntimeEndpoint: "unix:///run/docker.sock", BootID: "boot_0123456789abcdef", Token: func() ([]byte, error) { return []byte("one-original-secret-token"), nil }, Probe: func(context.Context) (string, error) { return "docker-original", nil }}
	p := &platform{binding: transport.InstallationBinding{TenantID: o.TenantID, RunnerDeploymentID: o.PoolID, InstallationID: "enrollment:original", Identity: protocol.HostIdentity{HostId: "11111111-1111-4111-8111-111111111111", KeyId: "22222222-2222-4222-8222-222222222222", KeyVersion: "1", SessionEpoch: "1"}}}
	return o, p
}
func TestInterruptedSetupKeepsOriginalIdentity(t *testing.T) {
	for _, point := range []string{"before-key", "after-key", "after-attempt", "after-enrollment-response", "before-credentials", "after-credentials", "after-config"} {
		t.Run(point, func(t *testing.T) {
			o, p := fixture(t)
			o.Checkpoint = func(s string) error {
				if s == point {
					return errors.New("interrupted")
				}
				return nil
			}
			if _, e := Setup(context.Background(), p, o); e == nil {
				t.Fatal("fault did not interrupt")
			}
			seed, _ := os.ReadFile(filepath.Join(o.SetupDir, "original-key.seed"))
			o.Checkpoint = nil
			b, e := Setup(context.Background(), p, o)
			if e != nil {
				t.Fatal(e)
			}
			if p.effects != 1 || b.InstallationID != "enrollment:original" {
				t.Fatal("replacement installation")
			}
			after, _ := os.ReadFile(filepath.Join(o.SetupDir, "original-key.seed"))
			if len(seed) > 0 && string(seed) != string(after) {
				t.Fatal("original key changed")
			}
			before, _ := os.ReadFile(o.CredentialPath)
			o.Token = func() ([]byte, error) { t.Fatal("completed setup must not request token"); return nil, nil }
			if _, e = Setup(context.Background(), p, o); e != nil {
				t.Fatal(e)
			}
			afterCred, _ := os.ReadFile(o.CredentialPath)
			if string(before) != string(afterCred) || p.effects != 1 {
				t.Fatal("identity overwritten")
			}
			filepath.WalkDir(filepath.Dir(o.SetupDir), func(path string, d os.DirEntry, e error) error {
				if e == nil && !d.IsDir() {
					data, _ := os.ReadFile(path)
					if strings.Contains(string(data), "one-original-secret-token") {
						t.Error("secret persisted")
					}
					info, _ := os.Stat(path)
					if info.Mode().Perm() != 0600 {
						t.Error("unsafe file permissions")
					}
				}
				return e
			})
		})
	}
}
func TestLostResponseAndWrongRetryToken(t *testing.T) {
	o, p := fixture(t)
	p.lost = true
	if _, e := Setup(context.Background(), p, o); e == nil {
		t.Fatal("loss accepted")
	}
	o.Token = func() ([]byte, error) { return []byte("a-different-secret-token"), nil }
	if _, e := Setup(context.Background(), p, o); e == nil {
		t.Fatal("replacement token accepted")
	}
	o.Token = func() ([]byte, error) { return []byte("one-original-secret-token"), nil }
	if _, e := Setup(context.Background(), p, o); e != nil {
		t.Fatal(e)
	}
	if p.calls != 2 || p.effects != 1 {
		t.Fatal("duplicate effect")
	}
}
func TestBindingAndExistingHistoryFailClosed(t *testing.T) {
	for _, change := range []string{"tenant", "pool", "session", "fingerprint", "request", "history", "symlink"} {
		t.Run(change, func(t *testing.T) {
			o, p := fixture(t)
			switch change {
			case "tenant":
				p.binding.TenantID = "other"
			case "pool":
				p.binding.RunnerDeploymentID = "other"
			case "history":
				_ = os.WriteFile(filepath.Join(o.StateDir, "existing-history"), []byte("retain"), 0600)
			case "symlink":
				_ = os.Symlink("/etc/passwd", o.CredentialPath)
			default:
				o.Checkpoint = func(s string) error {
					if s == "after-enrollment-response" {
						switch change {
						case "session":
							p.binding.Identity.SessionEpoch = "2"
						case "fingerprint":
							p.binding.PublicKeyFingerprint = strings.Repeat("0", 64)
						case "request":
							p.binding.EnrollmentRequestID = "different"
						}
					}
					return nil
				}
			}
			if _, e := Setup(context.Background(), p, o); e == nil {
				t.Fatal("conflicting authority accepted")
			}
			if _, e := os.Lstat(o.ConfigPath); !os.IsNotExist(e) {
				t.Fatal("configuration written")
			}
		})
	}
}
func TestOriginalPeerAndCredentialCannotBeReplaced(t *testing.T) {
	o, p := fixture(t)
	if _, e := Setup(context.Background(), p, o); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(o.CredentialPath)
	o.Probe = func(context.Context) (string, error) { return "replacement-peer", nil }
	if _, e := Setup(context.Background(), p, o); e == nil {
		t.Fatal("peer silently rebound")
	}
	after, _ := os.ReadFile(o.CredentialPath)
	if string(raw) != string(after) {
		t.Fatal("credentials changed")
	}
	c, k, e := execution.ReadCredentials(o.CredentialPath)
	if e != nil || c.EndpointIdentity != "docker-original" {
		t.Fatal(e)
	}
	if _, e = x509.MarshalPKCS8PrivateKey(k); e != nil {
		t.Fatal(e)
	}
	clear(k)
}
