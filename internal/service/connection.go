package service

import (
	"context"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/onboarding"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

type connectionStatus struct {
	sync.Mutex
	state, heartbeat string
}

func (s *connectionStatus) set(state, heartbeat string) {
	s.Lock()
	defer s.Unlock()
	s.state = state
	if heartbeat != "" {
		s.heartbeat = heartbeat
	}
}
func (s *connectionStatus) get() (string, string) {
	s.Lock()
	defer s.Unlock()
	return s.state, s.heartbeat
}

// connect reports zero capacity and no supported profiles. It never opens the
// mutating engine, pulls/acks commands, or emits execution/cleanup evidence.
func connect(ctx context.Context, c config.Config, status *connectionStatus) {
	credentials, key, e := execution.ReadCredentials(c.CredentialFile)
	if e != nil {
		status.set("identity-invalid", "")
		return
	}
	defer clear(key)
	client, e := transport.New(c.ControlPlaneURL, c.Timeout())
	if e != nil {
		status.set("configuration-invalid", "")
		return
	}
	defer client.Close()
	engine, e := dockerengine.OpenReadOnly(c.RuntimeEndpoint, credentials.InstallationID, func() {})
	if e != nil {
		status.set("runtime-unavailable", "")
		return
	}
	defer engine.Close()
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		status.set("boot-unavailable", "")
		return
	}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		status.set("connecting", "")
		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		binding, e := engine.Probe(requestCtx)
		if e != nil || binding != credentials.EndpointIdentity {
			status.set("runtime-continuity-recovery-required", "")
			cancel()
			return
		}
		access, err := onboarding.Authenticate(requestCtx, client, key, credentials.Identity, strings.TrimSpace(string(boot)))
		if err == nil {
			installation, x := client.Installation(requestCtx, access)
			err = x
			b := c.Connection
			if err == nil && (installation.Identity != credentials.Identity || installation.InstallationID != credentials.InstallationID || installation.TenantID != credentials.TenantID || installation.TenantID != b.TenantID || installation.RunnerDeploymentID != b.RunnerDeploymentID || installation.EnrollmentRequestID != b.EnrollmentRequestID || installation.PublicKeyFingerprint != b.PublicKeyFingerprint) {
				err = onboarding.ErrState
			}
		}
		if err == nil {
			var proposal protocol.ConfigResponse
			data, x := client.Config(requestCtx, access)
			err = x
			if err == nil {
				proposal, err = protocol.DecodeConfigResponse(data)
			}
			if err == nil {
				capabilities := protocol.HostCapabilities{Host: protocol.Platform{Os: "linux", Architecture: protocol.PlatformArchitecture(runtime.GOARCH), Build: "unqualified"}, Engine: protocol.Platform{Os: "linux", Architecture: protocol.PlatformArchitecture(runtime.GOARCH), Build: "unqualified"}, EndpointIdentity: binding, RuntimeVersion: "unqualified-observation", ConfigurationGeneration: "1", ProbeGeneration: "1", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Profiles: []string{}, SupportedImageFamilies: []string{}, RuntimeMechanism: "docker", Capacity: protocol.ResourceBudget{CpuMillis: "0", MemoryBytes: "0", StorageBytes: "0", Slots: "0"}}
				m, x := protocol.EncodeValidated("HostHeartbeat", map[string]any{"identity": credentials.Identity, "agentVersion": execution.Version(), "protocolVersion": "1.0.0", "inventoryGeneration": "1", "effectivePolicyGeneration": proposal.Policy.Generation, "capabilities": capabilities})
				err = x
				if err == nil {
					_, err = client.Post(requestCtx, "/me/heartbeat", access, m, "ConfigResponse")
				}
			}
		}
		cancel()
		if err != nil {
			status.set("authentication-or-connection-failed", "")
		} else {
			status.set("connected", time.Now().UTC().Format(time.RFC3339Nano))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
