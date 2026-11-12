//go:build linux

package broker

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

// Component fixture bypasses only mount provisioning, not file/type checks.
func handoffFixture(t *testing.T) (*handoffManager, dockerengine.Plan, string, string) {
	t.Helper()
	l, _ := testLedger(t)
	source, target := t.TempDir(), t.TempDir()
	_ = os.Chmod(source, 0700)
	_ = os.Chmod(target, 0700)
	s, err := os.OpenRoot(source)
	if err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(); r.Close() })
	p := dockerengine.Plan{Name: "nrd-" + strings.Repeat("a", 64)}
	if err = os.Mkdir(filepath.Join(source, p.Name), 0700); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"jit": "fixture-only", "expiresAt": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano), "organization": "Neticora", "repository": "Neticora/project", "pool": "pool-a"})
	if err = os.WriteFile(filepath.Join(source, p.Name, "bootstrap.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	return &handoffManager{ledger: l, source: s, root: r, uid: os.Geteuid(), boot: "fixture-boot", organization: "Neticora", repository: "Neticora/project", pool: "pool-a"}, p, source, target
}

func TestHandoffSnapshotsAndPreservesUnknownContent(t *testing.T) {
	m, p, source, target := handoffFixture(t)
	if err := m.Prepare(p); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(target, p.Name, "bootstrap.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(source, p.Name, "bootstrap.json"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = m.Prepare(p); err != nil {
		t.Fatal("source update replaced protected snapshot", err)
	}
	current, err := os.ReadFile(filepath.Join(target, p.Name, "bootstrap.json"))
	if err != nil || string(current) != string(original) {
		t.Fatal("snapshot changed", err)
	}
	if err = os.WriteFile(filepath.Join(target, p.Name, "unrecognized"), []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = m.Dispose(p); !errors.Is(err, ErrQuarantined) {
		t.Fatal("unknown content deleted", err)
	}
	if _, err = os.Stat(filepath.Join(target, p.Name, "unrecognized")); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(target, p.Name, "unrecognized")); err != nil {
		t.Fatal(err)
	}
	if err = m.Dispose(p); err != nil {
		t.Fatal(err)
	}
	if err = m.CheckDisposed(p); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(target, p.Name), 0700); err != nil {
		t.Fatal(err)
	}
	if err = m.CheckDisposed(p); err == nil {
		t.Fatal("reappeared directory accepted")
	}
}

func TestHandoffRefusesSymlinksHardlinksDevicesAndUnownedContent(t *testing.T) {
	for _, attack := range []string{"symlink", "hardlink", "fifo", "directory", "readable-by-group", "invalid-json", "wrong-owner"} {
		t.Run(attack, func(t *testing.T) {
			m, p, source, target := handoffFixture(t)
			file := filepath.Join(source, p.Name, "bootstrap.json")
			if attack == "wrong-owner" {
				m.uid++
			} else if attack == "readable-by-group" {
				if err := os.Chmod(file, 0640); err != nil {
					t.Fatal(err)
				}
			} else if attack == "invalid-json" {
				if err := os.WriteFile(file, []byte(`{"jit":"x","jit":"y"}`), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				secret := filepath.Join(source, "private-fixture")
				if err := os.WriteFile(secret, []byte("must-not-copy"), 0600); err != nil {
					t.Fatal(err)
				}
				var err error
				switch attack {
				case "symlink":
					err = os.Symlink(secret, file)
				case "hardlink":
					err = os.Link(secret, file)
				case "fifo":
					err = syscall.Mkfifo(file, 0600)
				case "directory":
					err = os.Mkdir(file, 0700)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := m.Prepare(p); err == nil {
				t.Fatal("unsafe handoff accepted")
			}
			if _, err := os.Stat(filepath.Join(target, p.Name)); !os.IsNotExist(err) {
				t.Fatal("unsafe input produced privileged snapshot", err)
			}
		})
	}
}
