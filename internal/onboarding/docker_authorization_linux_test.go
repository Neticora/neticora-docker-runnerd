//go:build linux

package onboarding

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

func TestDockerAuthorizationHandoffPreservesOriginalSetup(t *testing.T) {
	o, p, _, seed := unfinishedSetup(t)
	path := filepath.Join(o.SetupDir, "attempt.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	o.Probe = func(context.Context) (string, error) { return "", errAuthorizeDocker }
	o.Token = func() ([]byte, error) { t.Fatal("authorization requested an enrollment token"); return nil, nil }
	if _, err = Setup(context.Background(), p, o); !errors.Is(err, errAuthorizeDocker) {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	afterSeed, _ := os.ReadFile(filepath.Join(o.SetupDir, "original-key.seed"))
	defer clear(afterSeed)
	if !bytes.Equal(before, after) || !bytes.Equal(seed, afterSeed) || p.calls != 0 || p.effects != 0 {
		t.Fatal("authorization handoff changed the original attempt/key or contacted enrollment")
	}
}

func TestDockerAuthorizationRequiresApprovalAndIsIdempotent(t *testing.T) {
	for _, mode := range []string{"declined", "input-error", "approved", "grant-failed", "grant-not-effective", "already-member", "concurrent-grant", "socket-changed", "account-changed"} {
		t.Run(mode, func(t *testing.T) {
			identity := serviceIdentity{uid: 982, gid: 982}
			socket := dockerSocketAuthorization{path: "/run/docker.sock", group: 989, stat: syscall.Stat_t{Dev: 1, Ino: 2, Mode: syscall.S_IFSOCK | 0660, Gid: 989}}
			if mode == "already-member" {
				identity.groups = []uint32{989}
			}
			prompts, grants, observations := 0, 0, 0
			confirm := func() (bool, error) {
				prompts++
				if mode == "input-error" {
					return false, errors.New("terminal ended")
				}
				if mode == "concurrent-grant" {
					identity.groups = []uint32{989}
				}
				if mode == "account-changed" {
					identity.uid++
				}
				return mode != "declined", nil
			}
			grant := func() error {
				grants++
				if mode == "grant-failed" {
					return ErrAuthorizationFailed
				}
				if mode != "grant-not-effective" {
					identity.groups = []uint32{989}
				}
				return nil
			}
			inspect := func(string) (dockerSocketAuthorization, error) {
				observations++
				copy := socket
				if observations > 1 && mode == "socket-changed" {
					copy.stat.Ino++
				}
				return copy, nil
			}
			err := approveDockerAccess("unix:///run/docker.sock", confirm, grant, func() (serviceIdentity, error) { return identity, nil }, inspect)
			if mode == "approved" || mode == "concurrent-grant" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unsafe/failed authorization accepted")
			}
			expectedGrants := 0
			if mode == "approved" || mode == "grant-failed" || mode == "grant-not-effective" {
				expectedGrants = 1
			}
			if grants != expectedGrants {
				t.Fatalf("unexpected grant count %d", grants)
			}
			if mode == "already-member" && prompts != 0 {
				t.Fatal("already authorized account prompted")
			}
			if mode == "socket-changed" && !errors.Is(err, dockerengine.ErrContinuity) {
				t.Fatal(err)
			}
			if mode == "account-changed" && !errors.Is(err, ErrServiceIdentity) {
				t.Fatal(err)
			}
			if mode == "approved" {
				_ = approveDockerAccess("unix:///run/docker.sock", confirm, grant, func() (serviceIdentity, error) { return identity, nil }, inspect)
				if grants != 1 || prompts != 1 {
					t.Fatal("repeated authorization changed membership or prompted")
				}
			}
		})
	}
}

func TestSetupFramesRejectUnknownOrOversizedInputs(t *testing.T) {
	for _, input := range []string{`{"endpoint":"unix:///run/docker.sock","token":"forbidden"}`, `{"endpoint":"` + strings.Repeat("x", maxSetupFrame) + `"}`} {
		var request setupInputs
		if readSetupFrame(strings.NewReader(input), &request) == nil {
			t.Fatal("invalid private authorization frame accepted")
		}
	}
}
