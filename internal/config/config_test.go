package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/internal/stickycache"
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
		strings.Replace(valid, "{", "{\"execution\":{\"enabled\":true,\"brokerSocket\":\"/run/retired.sock\"},", 1),
	} {
		if _, err := Parse([]byte(raw)); err == nil || strings.Contains(err.Error(), "do-not-print-me") {
			t.Fatalf("unsafe configuration handling: %v", err)
		}
	}
}

func TestRuntimeHeadroomConfigurationCannotDisableProtectedMargin(t *testing.T) {
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
		valid := minimum == 0 || minimum >= 64<<20
		if (err == nil) != valid {
			t.Fatalf("invalid margin validation: %d %v", minimum, err)
		}
	}
}

func TestQualificationCampaignRequiresProtectedStandaloneConfiguration(t *testing.T) {
	c, _ := Parse([]byte(valid))
	c.Execution = &Execution{Enabled: true, Kata: &Kata{ProfileFile: "/etc/runnerd/profile.json", PublicKeyFile: "/etc/runnerd/public.pem", EvidenceDirectory: "/var/lib/evidence", StickyCache: &stickycache.Policy{VolumeGroup: "vg", ThinPool: "cache", PoolUUID: "pool-uuid", VolumeBytes: 8 << 30, Retain: 2, MaxDataPercent: 60, MaxMetaPercent: 60}, QualificationBindingFile: "/etc/runnerd/binding.json", QualificationAuthorityPin: strings.Repeat("a", 64)}, Repository: "org/repo", Organization: "org", Pool: "pool", PolicyFile: "/etc/runnerd/policy.json", CapabilitiesFile: "/etc/runnerd/capabilities.json", TrustRoots: "/etc/runnerd/roots", ImageBundles: "/etc/runnerd/bundles", ImageRepository: "registry/runner", NetworkID: "network", BootstrapRoot: "/run/bootstrap", KeysDirectory: "/var/lib/keys", TrustProvisionedAt: "2026-11-05T00:00:00Z", PidsLimit: 128}
	for _, name := range []string{"valid", "no cache", "no pin", "invalid pin", "journal binding", "guest binding", "guest health binding", "relative binding"} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(c)
			var next Config
			json.Unmarshal(raw, &next)
			q := next.Execution.Kata
			switch name {
			case "no cache":
				next.Execution.Kata.StickyCache = nil
			case "no pin":
				q.QualificationAuthorityPin = ""
			case "invalid pin":
				q.QualificationAuthorityPin = strings.Repeat("z", 64)
			case "journal binding":
				q.QualificationBindingFile = c.StateDir + "/binding.json"
			case "guest binding":
				q.QualificationBindingFile = c.Execution.BootstrapRoot + "/binding.json"
			case "guest health binding":
				q.QualificationBindingFile = c.Execution.BootstrapRoot + "-health/binding.json"
			case "relative binding":
				q.QualificationBindingFile = "binding.json"
			}
			raw, _ = json.Marshal(next)
			_, err := Parse(raw)
			if (err == nil) != (name == "valid") {
				t.Fatal(name, err)
			}
		})
	}
}
