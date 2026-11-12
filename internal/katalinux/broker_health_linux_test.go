//go:build linux

package katalinux

import (
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	"github.com/moby/moby/api/types/container"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBrokerHealthRetainsGuestOwnerAndRejectsSubstitution(t *testing.T) {
	base := t.TempDir()
	p := &Profile{brokerOwned: true, Base: standardlinux.Settings{BootstrapRoot: filepath.Join(base, "handoff"), RunnerUID: os.Geteuid()}}
	p.Manifest.Deadlines.StartupSeconds = 90
	p.Manifest.Deadlines.HeartbeatSeconds = 30
	p.Manifest.Deadlines.ExecutionSeconds = 600
	if err := os.Mkdir(p.HealthRoot(), 0700); err != nil {
		t.Fatal(err)
	}
	plan := dockerengine.Plan{Name: "nrd-" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Config: &container.Config{}}
	if err := p.PrepareHealth(plan); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	start := now.Add(-120 * time.Second).Format(time.RFC3339Nano)
	path := filepath.Join(p.HealthRoot(), plan.Name, "supervisor-health.json")
	raw := []byte(`{"version":"runnerd09-supervisor-health-v1","observedAt":"` + now.Format(time.RFC3339Nano) + `"}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if !p.Healthy(plan, start, now) {
		t.Fatal("valid guest health rejected")
	}
	os.Chmod(path, 0644)
	if p.Healthy(plan, start, now) {
		t.Fatal("unprotected guest health accepted")
	}
	os.Remove(path)
	outside := filepath.Join(base, "foreign.json")
	os.WriteFile(outside, raw, 0600)
	os.Symlink(outside, path)
	if p.Healthy(plan, start, now) {
		t.Fatal("symlink substituted for guest output")
	}
	os.Remove(path)
	os.WriteFile(path, raw, 0600)
	unexpected := filepath.Join(p.HealthRoot(), plan.Name, "unknown")
	os.WriteFile(unexpected, []byte("retain"), 0600)
	p.CleanHealth(plan)
	if _, err := os.Stat(unexpected); err != nil {
		t.Fatal("unknown guest output deleted", err)
	}
}
