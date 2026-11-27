// Package standardlinux defines the trusted-workload, process-only template.
// It neither administers host networking nor provides a Docker build endpoint.
package standardlinux

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

var ErrAdmission = errors.New("Standard Linux admission rejected")

const TemplateVersion = "linux-github-process-v1"

type Policy struct {
	value protocol.CustomerManagedPolicy
}

// ParsePolicy accepts the explicit customer-managed revision; legacy firewall
// assertions are never silently reinterpreted. The retained copy is immutable.
func ParsePolicy(raw []byte, previous *Policy) (*Policy, error) {
	p, err := protocol.DecodeCustomerManagedPolicy(raw)
	if err != nil {
		return nil, ErrAdmission
	}
	if previous != nil && number(p.Generation) <= number(previous.value.Generation) {
		return nil, ErrAdmission
	}
	for _, v := range []string{p.Limits.CpuMillis, p.Limits.MemoryBytes, p.Limits.StorageBytes, p.Limits.Slots} {
		if number(v) == 0 {
			return nil, ErrAdmission
		}
	}
	return &Policy{value: p}, nil
}
func (p *Policy) Generation() string { return p.value.Generation }
func (p *Policy) Limits() agent.ReservationLimits {
	return agent.ReservationLimits{CPUMillis: number(p.value.Limits.CpuMillis), MemoryBytes: number(p.value.Limits.MemoryBytes), StorageBytes: number(p.value.Limits.StorageBytes), Slots: min(number(p.value.Limits.Slots), number(p.value.MaxConcurrentExecutions))}
}
func (p *Policy) UID() int { return p.value.Restrictions.RunnerUid }

func (p *Policy) Transport(proxy, digest string, skew time.Duration, measured bool) error {
	w := p.value.Transport
	wantProxy, wantDigest := "", ""
	if w.ProxyUrl.IsSpecified() && !w.ProxyUrl.IsNull() {
		wantProxy = w.ProxyUrl.MustGet()
	}
	if w.CustomCaSha256.IsSpecified() && !w.CustomCaSha256.IsNull() {
		wantDigest = w.CustomCaSha256.MustGet()
	}
	if !measured || proxy != wantProxy || digest != wantDigest || skew > time.Duration(w.MaxClockSkewSeconds)*time.Second || skew < -time.Duration(w.MaxClockSkewSeconds)*time.Second {
		return ErrAdmission
	}
	return nil
}
func number(v string) uint64 { n, _ := strconv.ParseUint(v, 10, 64); return n }

// Admit only grants preparation eligibility. Fresh authority, policy/session
// checks and the store creation fence are still required immediately at launch.
func (p *Policy) Admit(scope agent.StoreScope, s protocol.ExecutionSpec, now time.Time) error {
	return p.admit(scope, s, now, false)
}

// AdmitIsolated shares policy/resource/session checks but never grants a runtime
// on its own. The Kata strategy additionally requires its signed physical tuple.
func (p *Policy) AdmitIsolated(scope agent.StoreScope, s protocol.ExecutionSpec, now time.Time) error {
	return p.admit(scope, s, now, true)
}

func (p *Policy) admit(scope agent.StoreScope, s protocol.ExecutionSpec, now time.Time, isolated bool) error {
	b, err := json.Marshal(s)
	if err != nil || protocol.ValidateInboundJSON("ExecutionSpec", b) != nil {
		return ErrAdmission
	}
	if p == nil {
		return ErrAdmission
	}
	w := p.value
	expires, err := time.Parse(time.RFC3339Nano, s.AuthorizationExpiresAt)
	if err != nil || !expires.After(now) || s.PolicyGeneration != w.Generation || !slices.Contains(w.AllowedTenantIds, scope.TenantID) || !slices.Contains(w.AllowedPoolIds, s.PoolId) || !slices.Contains(w.AllowedProfiles, s.ProfileVersion) || !slices.Contains(w.Images.AllowedDigests, s.ImageDigest) {
		return ErrAdmission
	}
	trusted := false
	for _, v := range w.AllowedTrustClasses {
		if v == "trusted" {
			trusted = true
		}
	}
	profileOK := s.IsolationProfile == "standard" && s.TemplateVersion == TemplateVersion && !s.DockerBuild
	if isolated {
		profileOK = s.IsolationProfile == "isolated" && (s.TemplateVersion == "linux-github-kata-v1" || s.TemplateVersion == "linux-github-kata-v2") && s.DockerBuild
	}
	if !trusted || s.TrustClass != "trusted" || s.Provider != "github" || s.ExecutionBackend != "customer-host" || s.RuntimeEngine != "docker" || !profileOK || s.RunnerPlatform.Os != "linux" || s.HostPlatform.Os != "linux" || s.RunnerPlatform.Architecture != s.HostPlatform.Architecture || s.RunnerPlatform.Architecture != "amd64" {
		return ErrAdmission
	}
	for _, pair := range [][2]string{{s.Resources.CpuMillis, w.Limits.CpuMillis}, {s.Resources.MemoryBytes, w.Limits.MemoryBytes}, {s.Resources.StorageBytes, w.Limits.StorageBytes}, {s.Resources.Slots, w.Limits.Slots}} {
		if number(pair[0]) == 0 || number(pair[0]) > number(pair[1]) {
			return ErrAdmission
		}
	}
	if number(s.Resources.Slots) != 1 || number(s.Resources.MemoryBytes) > math.MaxInt64 || number(s.Resources.StorageBytes) > math.MaxInt64 || number(s.Resources.CpuMillis) > math.MaxInt64/1_000_000 {
		return ErrAdmission
	}
	return nil
}

type Settings struct {
	ImageRepository string
	NetworkID       string // Existing customer-provisioned Docker bridge ID, never host.
	BootstrapRoot   string // Provisioned private tmpfs directory, outside journal.
	RunnerUID       int
	PidsLimit       int64
}

func (s Settings) Plan(scope agent.StoreScope, spec protocol.ExecutionSpec) (dockerengine.Plan, error) {
	if s.ImageRepository == "" || strings.ContainsAny(s.ImageRepository, "@ \t\r\n") || s.NetworkID == "" || s.NetworkID == "host" || s.NetworkID == "none" || strings.HasPrefix(s.NetworkID, "container:") || s.RunnerUID < 1 || s.PidsLimit < 16 || s.PidsLimit > 4096 || !filepath.IsAbs(s.BootstrapRoot) || filepath.Clean(s.BootstrapRoot) != s.BootstrapRoot {
		return dockerengine.Plan{}, ErrAdmission
	}
	identity := agent.Identity{InstallationID: scope.InstallationID, TenantID: scope.TenantID, HostID: scope.HostID, ExecutionID: spec.ExecutionId, Generation: spec.Generation, SpecHash: spec.SpecHash, AttemptID: spec.AttemptId}
	labels := map[string]string{}
	labels[dockerengine.LabelPrefix+"docker-build"] = "false"
	labels[dockerengine.LabelPrefix+"hard-storage-limit"] = "false"
	for k, v := range map[string]string{"installation": identity.InstallationID, "tenant": identity.TenantID, "host": identity.HostID, "execution": identity.ExecutionID, "generation": identity.Generation, "spec": identity.SpecHash, "attempt": identity.AttemptID, "endpoint": scope.EndpointIdentity, "template": TemplateVersion} {
		labels[dockerengine.LabelPrefix+k] = v
	}
	hash := sha256.Sum256([]byte(scope.InstallationID + "\x00" + spec.ExecutionId + "\x00" + spec.Generation + "\x00" + spec.SpecHash))
	name := "nrd-" + hex.EncodeToString(hash[:])
	pids := s.PidsLimit
	return dockerengine.Plan{Name: name, Config: &container.Config{Image: s.ImageRepository + "@" + spec.ImageDigest, User: strconv.Itoa(s.RunnerUID) + ":" + strconv.Itoa(s.RunnerUID), WorkingDir: "/runner", Entrypoint: []string{"/usr/local/bin/runnerd-github"}, Labels: labels}, HostConfig: &container.HostConfig{
		RestartPolicy: container.RestartPolicy{Name: "no"}, Runtime: "runc", CgroupnsMode: "private", NetworkMode: container.NetworkMode(s.NetworkID), IpcMode: "private", CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges=true"},
		Resources: container.Resources{NanoCPUs: int64(number(spec.Resources.CpuMillis)) * 1_000_000, Memory: int64(number(spec.Resources.MemoryBytes)), MemorySwap: int64(number(spec.Resources.MemoryBytes)), PidsLimit: &pids},
		Mounts:    []mount.Mount{{Type: mount.TypeBind, Source: filepath.Join(s.BootstrapRoot, name), Target: "/run/neticora-bootstrap", BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate}}},
		Tmpfs:     map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=67108864", "/runner/_work": fmt.Sprintf("rw,nosuid,nodev,size=%d,uid=%d,gid=%d,mode=0700", number(spec.Resources.StorageBytes), s.RunnerUID, s.RunnerUID)},
		LogConfig: container.LogConfig{Type: "local", Config: map[string]string{"max-size": "10m", "max-file": "2", "mode": "non-blocking", "max-buffer-size": "1m"}},
	}}, nil
}
