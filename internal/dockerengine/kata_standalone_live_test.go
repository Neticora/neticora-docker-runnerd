//go:build linux

package dockerengine

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
)

func TestStandaloneLiveDockerRuntime(t *testing.T) {
	if os.Getenv("NETICORA_PHASE2_LAB_DOCKER") != "1" {
		t.Skip("requires the dedicated runnerd-kata lab")
	}
	if host, err := os.Hostname(); err != nil || host != "neticora-runnerd-kata" || os.Geteuid() != 0 {
		t.Fatal("dedicated runnerd-kata lab root required")
	}
	const daemon = "/etc/docker/daemon.json"
	const runtimeConfig = "/etc/kata-containers/phase1-qemu.toml"
	const selector = "phase1-kata"
	shim := os.Getenv("NETICORA_PHASE2_LAB_KATA_SHIM")
	if shim == "" {
		t.Fatal("expected signed runtime path required")
	}
	raw, err := os.ReadFile(daemon)
	if err != nil {
		t.Fatal(err)
	}
	e, err := OpenStandalone("unix:///run/docker.sock", "phase2-direct-engine-read-only-check", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx := t.Context()
	identity, err := e.Probe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.CheckKataHostCgroupDriver(ctx); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	if err := e.CheckStandaloneKataTuple(ctx, selector, "29.10.0", "/var/lib/docker", shim, runtimeConfig, daemon, digest); err != nil {
		t.Fatal(err)
	}
	if err := e.CheckStandaloneKataTuple(ctx, selector, "29.10.0", "/var/lib/docker", shim, runtimeConfig, daemon, fmt.Sprintf("%064x", 0)); err == nil {
		t.Fatal("changed daemon configuration accepted")
	}
	t.Logf("verified direct engine %s on overlayfs with signed runtime %s, private API, and systemd cgroup v2", identity, selector)
}
