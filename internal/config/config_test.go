package config

import (
	"encoding/json"
	"strings"
	"testing"
)

const valid = `{"controlPlaneUrl":"https://example.invalid/hosts","stateDir":"/var/lib/neticora-runnerd","runtimeEndpoint":"unix:///run/docker.sock","credentialFile":"/etc/neticora-runnerd/identity.json","requestTimeoutSeconds":15}`

func TestStrictConfiguration(t *testing.T) {
	if _, err := Parse([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(valid, "https://", "http://", 1), strings.Replace(valid, "example.invalid", "secret@example.invalid", 1),
		strings.Replace(valid, "unix:///run/docker.sock", "tcp://localhost:2375", 1),
		strings.Replace(valid, "/etc/neticora-runnerd/identity.json", "/var/lib/neticora-runnerd/identity.json", 1),
		strings.Replace(valid, "/var/lib/neticora-runnerd", "/var/lib/../neticora-runnerd", 1),
		strings.Replace(valid, "\"requestTimeoutSeconds\":15", "\"requestTimeoutSeconds\":0", 1),
		strings.Replace(valid, "\"requestTimeoutSeconds\":15", "\"requestTimeoutSeconds\":999", 1),
		strings.Replace(valid, "{", "{\"secret\":\"do-not-print-me\",", 1),
		strings.Replace(valid, "{", "{\"stateDir\":\"duplicate\",", 1),
	} {
		if _, err := Parse([]byte(raw)); err == nil || strings.Contains(err.Error(), "do-not-print-me") {
			t.Fatalf("unsafe configuration handling: %v", err)
		}
	}
}

func TestLegacyHeadroomInputDoesNotImposeStoragePolicy(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	c.Execution = &Execution{Enabled: true, Repository: "org/repo", Organization: "org", Pool: "pool", PolicyFile: "/etc/runnerd/policy.json", CapabilitiesFile: "/etc/runnerd/capabilities.json", TrustRoots: "/etc/runnerd/roots", ImageBundles: "/etc/runnerd/bundles", ImageRepository: "registry/runner", NetworkID: "customer-network", BootstrapRoot: "/run/runnerd-bootstrap", KeysDirectory: "/var/lib/runnerd-keys", TrustProvisionedAt: "2026-11-05T00:00:00Z", PidsLimit: 128}
	for _, minimum := range []uint64{0, 1, 64<<20 - 1, 64 << 20, 256 << 20} {
		c.Execution.MinRuntimeFreeBytes = minimum
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Parse(raw)
		valid := true
		if (err == nil) != valid {
			t.Fatalf("invalid margin validation: %d %v", minimum, err)
		}
	}
}

func TestPreparationValidatesDisabledConfigurationBeforeActivation(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParsePreparation([]byte(valid)); err == nil {
		t.Fatal("missing execution accepted")
	}
	c.Execution = &Execution{Enabled: false, Repository: "org/repo", Organization: "org", Pool: "pool", PolicyFile: "/etc/runnerd/policy.json", CapabilitiesFile: "/etc/runnerd/capabilities.json", TrustRoots: "/etc/runnerd/roots", ImageBundles: "/etc/runnerd/bundles", ImageRepository: "registry/runner", NetworkID: "customer-network", BootstrapRoot: "/run/runnerd-bootstrap", KeysDirectory: "/var/lib/runnerd-keys", TrustProvisionedAt: "2026-11-15T00:00:00Z", PidsLimit: 128}
	raw, _ := json.Marshal(c)
	if _, err = ParsePreparation(raw); err != nil {
		t.Fatal(err)
	}
	c.Execution.Repository = "org"
	raw, _ = json.Marshal(c)
	if _, err = ParsePreparation(raw); err != nil {
		t.Fatal(err)
	}
	c.Execution.Repository = "org/repo"
	for _, mutate := range []func(*Execution){func(x *Execution) { x.Enabled = true }, func(x *Execution) { x.PidsLimit = 0 }, func(x *Execution) { x.NetworkID = "host" }, func(x *Execution) { x.NetworkID = "container:other" }, func(x *Execution) { x.ImageRepository = "image@sha256:unapproved" }, func(x *Execution) { x.PolicyFile = "relative" }, func(x *Execution) { x.BootstrapRoot = "/etc/runnerd" }, func(x *Execution) { x.Repository = "other/repo" }, func(x *Execution) { x.TrustProvisionedAt = "invalid" }} {
		candidate := c
		copy := *c.Execution
		candidate.Execution = &copy
		mutate(candidate.Execution)
		raw, _ = json.Marshal(candidate)
		if _, err = ParsePreparation(raw); err == nil {
			t.Fatalf("unsafe preparation accepted: %+v", candidate.Execution)
		}
	}
}

func TestDiskStorageCannotExposeJournalSecretsOrDockerBackingPaths(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	c.Execution = &Execution{Enabled: false, Repository: "org/repo", Organization: "org", Pool: "pool", PolicyFile: "/etc/runnerd/policy.json", CapabilitiesFile: "/etc/runnerd/caps.json", TrustRoots: "/etc/runnerd/roots", ImageBundles: "/etc/runnerd/bundles", ImageRepository: "registry/runner", NetworkID: "existing-bridge", BootstrapRoot: "/run/bootstrap", KeysDirectory: "/var/lib/runnerd-keys", TrustProvisionedAt: "2026-11-15T00:00:00Z", PidsLimit: 128, StorageRoot: "/mnt/neticora-runners/executions", RuntimeStoragePaths: []string{"/var/lib/docker", "/var/lib/containerd"}}
	raw, _ := json.Marshal(c)
	if _, err = ParsePreparation(raw); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{"/", "relative", "/var/lib", "/etc", "/run/bootstrap", "/var/lib/docker/jobs", "/mnt/neticora-runners/executions/../cache"} {
		c.Execution.StorageRoot = root
		raw, _ = json.Marshal(c)
		if _, err = ParsePreparation(raw); err == nil {
			t.Fatal("unsafe storage root accepted", root)
		}
	}
	c.Execution.StorageRoot = "/mnt/neticora-runners/executions"
	c.Execution.RuntimeStoragePaths = nil
	raw, _ = json.Marshal(c)
	if _, err = ParsePreparation(raw); err != nil {
		t.Fatal("optional backing observations became topology requirement", err)
	}
}
