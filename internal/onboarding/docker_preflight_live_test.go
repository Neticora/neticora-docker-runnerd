//go:build linux && runnerd_docker

package onboarding

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

// Run as the installed service UID/GID with all supplementary groups cleared,
// before the operator grants access. Token input and platform effects must remain
// absent even though the standard root-owned systemd Docker daemon is healthy.
func TestInstalledAccountDockerPreflightCannotConsumeToken(t *testing.T) {
	if os.Getenv("RUNNERD_SOCKET_ACTIVATION_TEST") != "1" || os.Getenv("RUNNERD_SOCKET_EXPECT_DENIED") != "1" {
		t.Skip("explicit denied-account VM fixture required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal("disposable VM required")
	}
	for _, retained := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "saved-original-response"}[retained], func(t *testing.T) {
			o, p := fixture(t)
			before := map[string][]byte{}
			if retained {
				o.Checkpoint = func(point string) error {
					if point == "before-credentials" {
						return errors.New("retained original response")
					}
					return nil
				}
				if _, err := Setup(context.Background(), p, o); err == nil {
					t.Fatal("expected interrupted setup")
				}
				o.Checkpoint = nil
				for _, name := range []string{"attempt.json", "original-key.seed", "enrollment.json"} {
					path := filepath.Join(o.SetupDir, name)
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					before[path] = raw
				}
			}
			effects, calls := p.effects, p.calls
			o.Probe = func(ctx context.Context) (string, error) {
				e, err := dockerengine.OpenReadOnly("unix:///run/docker.sock", "preflight-observation", func() {})
				if err != nil {
					return "", err
				}
				defer e.Close()
				return e.Probe(ctx)
			}
			o.Token = func() ([]byte, error) { t.Fatal("permission preflight requested a token"); return nil, nil }
			if _, err := Setup(context.Background(), p, o); !errors.Is(err, dockerengine.ErrPermission) {
				t.Fatal("specific real permission failure not retained", err)
			}
			if p.calls != calls || p.effects != effects {
				t.Fatal("failed preflight contacted enrollment")
			}
			for path, raw := range before {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(raw, after) {
					t.Fatal("original state changed")
				}
			}
			if !retained {
				for _, name := range []string{"attempt.json", "original-key.seed"} {
					if _, err := os.Stat(filepath.Join(o.SetupDir, name)); !os.IsNotExist(err) {
						t.Fatal("identity created before permission authorization")
					}
				}
			}
			for _, path := range []string{o.CredentialPath, o.ConfigPath} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("configuration created by denied preflight")
				}
			}
			t.Log("real service-account permission failure; token callback and platform effects unchanged; original state retained")
		})
	}
}
