//go:build linux

package katalinux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/moby/moby/api/types/container"
)

type sandboxGuardSnapshot struct {
	Profile  Profile           `json:"profile"`
	Plan     dockerengine.Plan `json:"plan"`
	Evidence Evidence          `json:"evidence"`
	Endpoint string            `json:"endpoint"`
	Network  string            `json:"network"`
	Peer     string            `json:"peer"`
}

func (s *sandboxGuardSnapshot) open(ctx context.Context, id string) (func() error, func(), error) {
	engine, err := dockerengine.OpenReadOnly(s.Endpoint, "runnerd09-cleanup-stress", nil)
	if err != nil {
		return nil, nil, err
	}
	close := func() { engine.Close() }
	if peer, err := engine.Probe(ctx); err != nil || peer != s.Peer {
		close()
		return nil, nil, ErrQualification
	}
	guard := s.Profile.cleanupSandboxGuard(ctx, s.Plan, s.Evidence, s.Profile.cleanupProcessGuard(ctx, id, s.Evidence, runtimeCleanupGuard(ctx, engine, id, s.Plan, s.Network, s.Peer)))
	return guard, close, nil
}

// Exercise the actual production guard functions on an absent synthetic ID and
// an empty owned cgroup. Docker calls are read-only. This is not a prior live-VM
// witness, a production qualification profile or a CLEANED-event fixture.
func sandboxProductionStressGuard(t *testing.T, ctx context.Context, p *Profile, directory, id string, capture ...*sandboxGuardSnapshot) func() error {
	t.Helper()
	endpoint := os.Getenv("RUNNERD09_STRESS_DOCKER_ENDPOINT")
	network := os.Getenv("RUNNERD09_STRESS_NETWORK_ID")
	if endpoint != "unix:///run/runnerd09-docker.sock" || len(network) != 64 {
		t.Fatal("explicit disposable Docker socket and full retained bridge ID required")
	}
	if decoded, err := hex.DecodeString(network); err != nil || hex.EncodeToString(decoded) != network {
		t.Fatal("exact network identity required")
	}
	engine, err := dockerengine.OpenReadOnly(endpoint, "runnerd09-cleanup-stress", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	expectedPeer, err := engine.Probe(ctx)
	if err != nil {
		t.Fatal("live Docker peer unavailable", err)
	}
	m := multiBlockFixture()
	m.Qualified = false
	m.SandboxRoots = []string{directory}
	m.Storage.Runtime.Root = directory
	m.Storage.Runtime.Device = p.Manifest.Storage.Runtime.Device
	m.HostCgroup.SystemctlBinary, m.HostCgroup.BusctlBinary = "/usr/bin/systemctl", "/usr/bin/busctl"
	for _, binary := range []string{m.HostCgroup.SystemctlBinary, m.HostCgroup.BusctlBinary} {
		raw, err := os.ReadFile(binary)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(raw)
		m.Files[binary] = hex.EncodeToString(hash[:])
	}
	*p = *profile(m)
	p.EvidenceDirectory = t.TempDir()
	if err := os.Chmod(p.EvidenceDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("runnerd09-metadata-stress:" + directory))
	name := "nrd-" + hex.EncodeToString(digest[:])
	plan := dockerengine.Plan{Name: name, HostConfig: &container.HostConfig{Resources: container.Resources{CgroupParent: hostCgroupUnit(name)}}}
	if err = p.prepareHostCgroup(ctx, plan); err != nil {
		t.Fatal("owned empty guard cgroup unavailable", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := p.releaseHostCgroup(cleanup, plan); err != nil {
			t.Error("owned empty guard cgroup cleanup", err)
		}
	})
	group, err := p.cgroupRecord(plan)
	if err != nil {
		t.Fatal(err)
	}
	evidence := Evidence{Prepared: true, Cgroup: &group}
	if len(capture) == 1 {
		*capture[0] = sandboxGuardSnapshot{*p, plan, evidence, endpoint, network, expectedPeer}
	}
	runtimeGuard := runtimeCleanupGuard(ctx, engine, id, plan, network, expectedPeer)
	guard := p.cleanupSandboxGuard(ctx, plan, evidence, p.cleanupProcessGuard(ctx, id, evidence, runtimeGuard))
	if err = guard(); err != nil {
		t.Fatal("production guard baseline failed", err)
	}
	if !strings.HasPrefix(group.Path, "/neticora.slice/neticora-runnerd.slice/") {
		t.Fatal("unconfined guard cgroup")
	}
	return guard
}
