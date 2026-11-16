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
	"github.com/Neticora/neticora-docker-runnerd/internal/connectionrecovery"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/onboarding"
	"github.com/Neticora/neticora-docker-runnerd/internal/telemetry"
	"github.com/Neticora/neticora-docker-runnerd/journal"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

type recoveryStatus struct{ operation, reason, epoch, boot, endpoint string }
type connectionStatus struct {
	recovery recoveryStatus
	sync.Mutex
	state, heartbeat string
	inventory        inventoryReport
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

func (s *connectionStatus) setRecovery(operation, reason, epoch, boot, endpoint string) {
	s.Lock()
	defer s.Unlock()
	s.recovery = recoveryStatus{operation, reason, epoch, boot, endpoint}
}
func (s *connectionStatus) recoveryStatus() recoveryStatus {
	s.Lock()
	defer s.Unlock()
	return s.recovery
}
func (s *connectionStatus) setInventory(report inventoryReport) {
	s.Lock()
	defer s.Unlock()
	s.inventory = report
}
func (s *connectionStatus) inventoryStatus() (inventoryReport, bool) {
	s.Lock()
	defer s.Unlock()
	report := s.inventory
	if report.Generation == "" {
		report.Generation = "0"
	}
	if report.State == "" {
		report.State = "unreported"
	}
	observed, err := time.Parse(time.RFC3339Nano, report.ObservedAt)
	age := time.Since(observed)
	return report, report.State == "accepted" && err == nil && age >= -5*time.Second && age <= inventoryFreshness
}

// connect reports zero capacity and no supported profiles. It never opens the
// mutating engine, pulls/acks commands, or emits execution/cleanup evidence.
func connect(ctx context.Context, c config.Config, status *connectionStatus, localEmpty func(context.Context) (bool, error), store *journal.SQLiteStore) {
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
	var observer *inventoryObserver
	paths := append([]string{c.StateDir}, c.ObservationPaths...)
	if c.Execution != nil {
		paths = append(paths, c.Execution.StorageRoot)
		paths = append(paths, c.Execution.RuntimeStoragePaths...)
	}
	sampler := &telemetry.Sampler{Paths: paths}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		status.set("connecting", "")
		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		engine, err := dockerengine.OpenReadOnly(c.RuntimeEndpoint, credentials.InstallationID, func() {})
		if err != nil {
			status.set("runtime-unavailable", "")
			cancel()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			continue
		}
		boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if e != nil {
			engine.Close()
			cancel()
			status.set("boot-unavailable", "")
			return
		}
		manager := connectionrecovery.Manager{Store: store, Runtime: engine, Remote: client, Config: c, Key: key, Boot: strings.TrimSpace(string(boot))}
		current, operation, reason, err := manager.Step(requestCtx, credentials)
		status.setRecovery(operation, reason, current.Identity.SessionEpoch, current.BootID, current.EndpointIdentity)
		if err != nil {
			observed, _ := engine.Probe(requestCtx)
			_ = connectionrecovery.ReportBlocked(requestCtx, c, current, key, client, reason, operation, observed)
			status.set("connection-resynchronization-blocked", "")
			report, _ := status.inventoryStatus()
			report.State = reason
			status.setInventory(report)
			engine.Close()
			cancel()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			continue
		}
		binding := current.EndpointIdentity
		if observer == nil || observer.identity != current.Identity || observer.endpoint != binding {
			observer = &inventoryObserver{remote: client, identity: current.Identity, endpoint: binding, localEmpty: localEmpty, hostname: os.Hostname, now: time.Now}
		}
		observer.runtime = engine
		access, err := onboarding.Authenticate(requestCtx, client, key, current.Identity, strings.TrimSpace(string(boot)))
		if err == nil {
			installation, x := client.Installation(requestCtx, access)
			err = x
			b := c.Connection
			if err == nil && (installation.Identity != current.Identity || installation.InstallationID != credentials.InstallationID || installation.TenantID != credentials.TenantID || installation.TenantID != b.TenantID || installation.RunnerDeploymentID != b.RunnerDeploymentID || installation.EnrollmentRequestID != b.EnrollmentRequestID || installation.PublicKeyFingerprint != b.PublicKeyFingerprint) {
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
				report, _ := observer.observe(requestCtx, access)
				status.setInventory(report)
				capabilities := protocol.HostCapabilities{Host: protocol.Platform{Os: "linux", Architecture: protocol.PlatformArchitecture(runtime.GOARCH), Build: "unqualified"}, Engine: protocol.Platform{Os: "linux", Architecture: protocol.PlatformArchitecture(runtime.GOARCH), Build: "unqualified"}, EndpointIdentity: binding, RuntimeVersion: "unqualified-observation", ConfigurationGeneration: "1", ProbeGeneration: "1", ObservedAt: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), Profiles: []string{}, SupportedImageFamilies: []string{}, RuntimeMechanism: "docker", Capacity: protocol.ResourceBudget{CpuMillis: "0", MemoryBytes: "0", StorageBytes: "0", Slots: "0"}}
				sample := sampler.Collect(requestCtx, binding, engine, nil, report.State == "accepted")
				m, x := protocol.EncodeValidated("HostHeartbeat", map[string]any{"telemetry": sample, "identity": current.Identity, "agentVersion": execution.Version(), "protocolVersion": "1.0.0", "inventoryGeneration": report.Generation, "effectivePolicyGeneration": proposal.Policy.Generation, "capabilities": capabilities})
				err = x
				if err == nil {
					_, err = client.Post(requestCtx, "/me/heartbeat", access, m, "ConfigResponse")
				}
			}
		}
		engine.Close()
		cancel()
		if err != nil {
			status.set("authentication-or-connection-failed", "")
			report, _ := status.inventoryStatus()
			report.State = "authentication-or-connection-failed"
			status.setInventory(report)
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
