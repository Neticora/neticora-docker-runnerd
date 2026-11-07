// Package katalinux implements the opt-in, independently qualified runtime-rs
// QEMU profile. Nothing here installs runtimes, mounts disks or changes networking.
package katalinux

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

const Template = "linux-github-kata-v1"
const Version = "runnerd09-kata-profile-v1"
const BlockVersion = "runnerd09-kata-profile-v2"
const MultiBlockVersion = "runnerd09-kata-profile-v3"
const BlockTemplate = "linux-github-kata-v2"

var ErrQualification = errors.New("Kata qualification or physical evidence unavailable")
var ErrObserverLifecycleBusy = errors.New("Kata observer lifecycle locked; explicit service start required after maintenance")

// Budget separates guest limits from total physically reserved host resources.
// ExecutionSpec.resources ALWAYS contains Effective, including VM overhead.
type Budget struct {
	Guest     protocol.ResourceBudget `json:"guest"`
	Overhead  protocol.ResourceBudget `json:"overhead"`
	Effective protocol.ResourceBudget `json:"effective"`
}
type Filesystem struct {
	UUID          string `json:"uuid,omitempty"`
	BackingDevice string `json:"backingDevice,omitempty"`
	Root          string `json:"root"`
	Device        uint64 `json:"device"`
	Bytes         uint64 `json:"bytes"`
}
type Storage struct {
	Block               *BlockStorage `json:"block,omitempty"`
	Graph               Filesystem    `json:"graph,omitzero"`
	Workspace           Filesystem    `json:"workspace,omitzero"`
	Runtime             Filesystem    `json:"runtime"`
	DockerRoot          string        `json:"dockerRoot"`
	OuterBytes          uint64        `json:"outerBytes"`
	LogBytes            uint64        `json:"logBytes"`
	ManagementFreeBytes uint64        `json:"managementFreeBytes"`
}
type Manifest struct {
	GuestStorageDriver      string    `json:"guestStorageDriver"`
	Deadlines               Deadlines `json:"deadlines"`
	Version                 string    `json:"version"`
	Qualified               bool      `json:"qualified"`
	EndpointIdentity        string    `json:"endpointIdentity"`
	ConfigurationGeneration string    `json:"configurationGeneration"`
	VerifiedAt              string    `json:"verifiedAt"`
	ExpiresAt               string    `json:"expiresAt"`
	HostKernel              string    `json:"hostKernel"`
	DockerVersion           string    `json:"dockerVersion"`
	RuntimeSelector         string    `json:"runtimeSelector"`
	RuntimeImplementation   string    `json:"runtimeImplementation"`
	Hypervisor              string    `json:"hypervisor"`
	DockerConfig            string    `json:"dockerConfig"`
	ObserverConfig          string    `json:"observerConfig"`
	RuntimeConfig           string    `json:"runtimeConfig"`
	HostOSFile              string    `json:"hostOSFile"`
	GuestKernel             string    `json:"guestKernel"`
	GuestImage              string    `json:"guestImage"`
	KataVersion             string    `json:"kataVersion"`
	QEMUVersion             string    `json:"qemuVersion"`
	GuestKernelVersion      string    `json:"guestKernelVersion"`
	GuestImageVersion       string    `json:"guestImageVersion"`
	ImageRepository         string    `json:"imageRepository"`
	ImageDigest             string    `json:"imageDigest"`
	// Every executable/configuration/rootfs involved in the accepted tuple is
	// pinned. Symlinks and writable inputs are rejected by the host observer.
	Files             map[string]string `json:"files"`
	QEMUBinary        string            `json:"qemuBinary"`
	ShimBinary        string            `json:"shimBinary"`
	VMNamePrefix      string            `json:"vmNamePrefix"`
	SandboxRoots      []string          `json:"sandboxRoots"`
	GuestCapabilities []string          `json:"guestCapabilities"`
	GuestDNSServers   []string          `json:"guestDnsServers,omitempty"`
	HostCgroup        *HostCgroup       `json:"hostCgroup,omitempty"`
	SecurityReview    string            `json:"securityReview"`
	Budget            Budget            `json:"budget"`
	Storage           Storage           `json:"storage"`
	// The authority records all original 14 and supplemental 24 cases. A runtime
	// registration string or guest-produced boolean can never populate this grant.
	Acceptance map[string]string `json:"acceptance"`
}
type Deadlines struct {
	StartupSeconds     int `json:"startupSeconds"`
	HeartbeatSeconds   int `json:"heartbeatSeconds"`
	TerminationSeconds int `json:"terminationSeconds"`
	ExecutionSeconds   int `json:"executionSeconds"`
}
type Signed struct {
	Manifest  Manifest `json:"manifest"`
	Signature string   `json:"signature"`
}
type Profile struct {
	// Profiles and cleanup-only reconciliation intentionally share the offline
	// Kata authority. Host authentication has a separate key and cannot grant either.
	storageAuthority      string
	storageInstallationID string
	storageHostID         string
	ObserverSocket        string
	Manifest              Manifest
	ID                    string
	EvidenceDirectory     string
	JournalDirectory      string
	Base                  standardlinux.Settings
}

// A separate sibling tmpfs directory carries guest liveness hints only. It is
// never part of the JIT/registration mount or trusted host evidence directory.
func (p *Profile) HealthRoot() string { return p.Base.BootstrapRoot + "-health" }

func ProfileID(m Manifest) (string, error) {
	b, e := json.Marshal(m)
	if e != nil {
		return "", e
	}
	b, e = protocol.CanonicalizeJSON(b)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	prefix := "docker-kata-rs-qemu-v1-"
	if m.Version == BlockVersion {
		prefix = "docker-kata-rs-qemu-v2-"
	}
	if m.Version == MultiBlockVersion {
		prefix = "docker-kata-rs-qemu-v3-"
	}
	return prefix + hex.EncodeToString(h[:]), nil
}
func Load(file, public, evidence, journal string, base standardlinux.Settings) (*Profile, error) {
	raw, e := hostfs.ReadPrivate(file, 131072)
	if e != nil {
		return nil, e
	}
	if _, e = protocol.CanonicalizeJSON(raw); e != nil {
		return nil, ErrQualification
	}
	var parts map[string]json.RawMessage
	if json.Unmarshal(raw, &parts) != nil || len(parts) != 2 || parts["manifest"] == nil || parts["signature"] == nil {
		return nil, ErrQualification
	}
	var signed Signed
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&signed) != nil {
		return nil, ErrQualification
	}
	keyRaw, e := hostfs.ReadPrivate(public, 16384)
	if e != nil {
		return nil, e
	}
	block, rest := pem.Decode(keyRaw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrQualification
	}
	k, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return nil, ErrQualification
	}
	key, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, ErrQualification
	}
	b, _ := json.Marshal(signed.Manifest)
	b, e = protocol.CanonicalizeJSON(b)
	original, rawErr := protocol.CanonicalizeJSON(parts["manifest"])
	sig, e2 := base64.RawURLEncoding.DecodeString(signed.Signature)
	if e != nil || rawErr != nil || !bytes.Equal(original, b) || e2 != nil || base64.RawURLEncoding.EncodeToString(sig) != signed.Signature || !ed25519.Verify(key, original, sig) {
		return nil, ErrQualification
	}
	id, e := ProfileID(signed.Manifest)
	if e != nil {
		return nil, e
	}
	p := &Profile{storageAuthority: public, Manifest: signed.Manifest, ID: id, EvidenceDirectory: evidence, JournalDirectory: journal, Base: base}
	if e = p.validate(); e != nil {
		return nil, e
	}
	if e = p.ProtectPaths(file, public); e != nil {
		return nil, e
	}
	return p, nil
}
func (p *Profile) validate() error {
	m := p.Manifest
	block := isBlockVersion(m.Version)
	if m.Version == MultiBlockVersion {
		if err := validateHostCgroup(m); err != nil {
			return err
		}
		if len(m.GuestDNSServers) < 1 || len(m.GuestDNSServers) > 4 {
			return ErrQualification
		}
		seen := map[string]bool{}
		for _, value := range m.GuestDNSServers {
			addr, err := netip.ParseAddr(value)
			if err != nil || !addr.Is4() || addr.String() != value || seen[value] {
				return ErrQualification
			}
			first := addr.As4()[0]
			if first == 0 || first == 127 || first >= 224 {
				return ErrQualification
			}
			seen[value] = true
		}
	} else if len(m.GuestDNSServers) != 0 || m.HostCgroup != nil {
		return ErrQualification
	}
	if (!block && (m.GuestStorageDriver != "vfs" || m.Storage.Block != nil)) || (block && (m.GuestStorageDriver != "overlay2" || p.validateBlockStorage() != nil)) {
		return ErrQualification
	}
	if m.Deadlines.StartupSeconds != 90 || m.Deadlines.HeartbeatSeconds != 30 || m.Deadlines.TerminationSeconds != 30 || m.Deadlines.ExecutionSeconds < 90 || m.Deadlines.ExecutionSeconds > 86400 {
		return ErrQualification
	}
	if m.RuntimeImplementation != "runtime-rs" || m.Hypervisor != "qemu" {
		return ErrQualification
	}
	for _, path := range []string{m.DockerConfig, m.ObserverConfig, m.RuntimeConfig, m.HostOSFile, m.GuestKernel, m.GuestImage, m.QEMUBinary, m.ShimBinary} {
		if m.Files[path] == "" {
			return ErrQualification
		}
	}
	if (m.Version != Version && !block) || !m.Qualified || !strings.HasPrefix(m.EndpointIdentity, "docker-") || m.ConfigurationGeneration == "" || m.HostKernel == "" || m.DockerVersion == "" || m.KataVersion == "" || m.QEMUVersion == "" || m.GuestKernelVersion == "" || m.GuestImageVersion == "" || m.RuntimeSelector == "" || m.RuntimeSelector == "runc" || m.RuntimeSelector == "default" || !validRuntimeSelector(m.RuntimeSelector) || len(m.Files) < 5 || m.Files[m.QEMUBinary] == "" || m.Files[m.ShimBinary] == "" || m.VMNamePrefix == "" || strings.ContainsAny(m.VMNamePrefix, "/ ,\x00") || len(m.SandboxRoots) == 0 || len(m.SecurityReview) < 20 {
		return ErrQualification
	}
	if m.ImageRepository == "" || strings.ContainsAny(m.ImageRepository, "@ \t\r\n") || len(m.ImageDigest) != 71 || !strings.HasPrefix(m.ImageDigest, "sha256:") {
		return ErrQualification
	}
	for _, path := range append(append([]string{}, m.SandboxRoots...), append([]string{p.EvidenceDirectory, p.JournalDirectory, m.Storage.DockerRoot}, p.storageRoots()...)...) {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return ErrQualification
		}
	}
	expectedCases := 38
	if block {
		expectedCases = 48
	}
	if len(m.Acceptance) != expectedCases {
		return ErrQualification
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(m.ImageDigest, "sha256:")); err != nil {
		return ErrQualification
	}
	for path, hash := range m.Files {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') || len(hash) != 64 {
			return ErrQualification
		}
		if _, err := hex.DecodeString(hash); err != nil {
			return ErrQualification
		}
	}
	roots := append(p.storageRoots(), m.Storage.DockerRoot)
	for i, root := range roots {
		for _, other := range roots[i+1:] {
			if overlappingPaths(root, other) {
				return ErrQualification
			}
		}
	}
	for _, root := range m.SandboxRoots {
		if root != m.Storage.Runtime.Root && !strings.HasPrefix(root, m.Storage.Runtime.Root+string(filepath.Separator)) {
			return ErrQualification
		}
	}
	protected := []string{p.JournalDirectory, p.EvidenceDirectory, p.Base.BootstrapRoot, p.HealthRoot()}
	for path := range m.Files {
		protected = append(protected, path)
	}
	if p.ProtectPaths(protected...) != nil {
		return ErrQualification
	}
	for _, group := range []struct {
		prefix string
		n      int
	}{{"original-", 14}, {"review-", 24}, {"storage-", expectedCases - 38}} {
		for i := 1; i <= group.n; i++ {
			if len(m.Acceptance[fmt.Sprintf("%s%02d", group.prefix, i)]) < 20 {
				return ErrQualification
			}
		}
	}
	for _, cap := range m.GuestCapabilities {
		if !slices.Contains([]string{"SETUID", "SETGID", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "NET_BIND_SERVICE", "NET_ADMIN", "SYS_ADMIN", "MKNOD", "SETPCAP", "NET_RAW", "SYS_CHROOT", "AUDIT_WRITE", "SETFCAP"}, cap) {
			return ErrQualification
		}
	}
	if !slices.Contains(m.GuestCapabilities, "SETUID") || !slices.Contains(m.GuestCapabilities, "SETGID") || !slices.Contains(m.GuestCapabilities, "CHOWN") {
		return ErrQualification
	}
	for _, field := range []func(protocol.ResourceBudget) string{func(b protocol.ResourceBudget) string { return b.CpuMillis }, func(b protocol.ResourceBudget) string { return b.MemoryBytes }, func(b protocol.ResourceBudget) string { return b.StorageBytes }} {
		g, e := strconv.ParseUint(field(m.Budget.Guest), 10, 64)
		o, e2 := strconv.ParseUint(field(m.Budget.Overhead), 10, 64)
		total, e3 := strconv.ParseUint(field(m.Budget.Effective), 10, 64)
		if e != nil || e2 != nil || e3 != nil || g == 0 || o == 0 || o > math.MaxInt64 || g > math.MaxInt64-o || g+o != total {
			return ErrQualification
		}
	}
	if m.Budget.Guest.Slots != "1" || m.Budget.Effective.Slots != "1" || m.Budget.Overhead.Slots != "0" || (!block && (m.Storage.Graph.Bytes == 0 || m.Storage.Workspace.Bytes == 0)) || m.Storage.Runtime.Bytes == 0 || m.Storage.OuterBytes == 0 || m.Storage.LogBytes != 20<<20 || m.Storage.ManagementFreeBytes < 256<<20 {
		return ErrQualification
	}
	cpu, _ := strconv.ParseUint(m.Budget.Guest.CpuMillis, 10, 64)
	memory, _ := strconv.ParseUint(m.Budget.Guest.MemoryBytes, 10, 64)
	if cpu%1000 != 0 || memory%(1<<20) != 0 {
		return ErrQualification
	}
	// Reserve the full dedicated filesystems, not sparse lengths or available
	// bytes. Saturation cannot spill into a shared graph/workspace filesystem.
	total := uint64(0)
	physical := []uint64{m.Storage.Runtime.Bytes, m.Storage.OuterBytes, m.Storage.LogBytes}
	if block {
		physical = append(physical, p.poolReservationBytes())
	} else {
		physical = append(physical, m.Storage.Graph.Bytes, m.Storage.Workspace.Bytes)
	}
	for _, v := range physical {
		if v > math.MaxInt64-total {
			return ErrQualification
		}
		total += v
	}
	budget, _ := strconv.ParseUint(m.Budget.Effective.StorageBytes, 10, 64)
	if total > budget {
		return ErrQualification
	}
	return nil
}

func overlappingPaths(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+string(filepath.Separator)) || strings.HasPrefix(b, a+string(filepath.Separator))
}

// Reject private state/trust paths on filesystems exposed to guest writes or
// recursively cleaned by the host helper. Runtime storage is equally disposable.
func (p *Profile) ProtectPaths(paths ...string) error {
	for _, path := range paths {
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return ErrQualification
		}
		for _, root := range append(p.storageRoots(), p.Manifest.Storage.DockerRoot) {
			if overlappingPaths(path, root) {
				return ErrQualification
			}
		}
	}
	return nil
}
func (p *Profile) Admit(scope agent.StoreScope, s protocol.ExecutionSpec, policy *standardlinux.Policy, now time.Time) error {
	if p == nil || p.Check(now) != nil || scope.EndpointIdentity != p.Manifest.EndpointIdentity || s.ProfileVersion != p.ID || s.TemplateVersion != p.template() || s.ImageDigest != p.Manifest.ImageDigest || s.Resources != p.Manifest.Budget.Effective {
		return ErrQualification
	}
	return policy.AdmitIsolated(scope, s, now)
}
func (p *Profile) Plan(scope agent.StoreScope, s protocol.ExecutionSpec) (dockerengine.Plan, error) {
	if err := p.RequireLaunchStorage(); err != nil {
		return dockerengine.Plan{}, err
	}
	return p.buildPlan(scope, s)
}

// RecoveryPlan reconstructs the exact historical configuration for inspection
// and cleanup. The engine rejects its use for image preparation, create or start.
func (p *Profile) RecoveryPlan(scope agent.StoreScope, s protocol.ExecutionSpec) (dockerengine.Plan, error) {
	plan, err := p.buildPlan(scope, s)
	if err != nil {
		return dockerengine.Plan{}, err
	}
	plan.RecoveryOnly = true
	return plan, nil
}

func (p *Profile) buildPlan(scope agent.StoreScope, s protocol.ExecutionSpec) (dockerengine.Plan, error) {
	if p == nil || s.IsolationProfile != "isolated" || s.TemplateVersion != p.template() || s.ProfileVersion != p.ID || s.ImageDigest != p.Manifest.ImageDigest || s.Resources != p.Manifest.Budget.Effective {
		return dockerengine.Plan{}, ErrQualification
	}
	plan, e := p.Base.Plan(scope, s)
	if e != nil {
		return plan, e
	}
	m := p.Manifest
	plan.Config.Image = m.ImageRepository + "@" + m.ImageDigest
	plan.Config.User = "0:0"
	plan.Config.Entrypoint = []string{"/usr/local/bin/runnerd-kata-supervisor"}
	for k, v := range map[string]string{"template": p.template(), "docker-build": "true", "hard-storage-limit": "true", "profile": p.ID} {
		plan.Config.Labels[dockerengine.LabelPrefix+k] = v
	}
	plan.HostConfig.Runtime = m.RuntimeSelector
	guestCPU, _ := strconv.ParseUint(m.Budget.Guest.CpuMillis, 10, 64)
	guestMemory, _ := strconv.ParseUint(m.Budget.Guest.MemoryBytes, 10, 64)
	if m.Version == MultiBlockVersion {
		// OCI limits describe the guest workload. The independently prepared
		// host slice constrains the VMM/runtime to the larger Effective budget.
		plan.HostConfig.NanoCPUs = int64(guestCPU * 1_000_000)
		plan.HostConfig.Memory = int64(guestMemory)
		plan.HostConfig.MemorySwap = int64(guestMemory)
		plan.HostConfig.CgroupParent = hostCgroupUnit(plan.Name)
	}
	plan.HostConfig.Annotations = map[string]string{
		"io.katacontainers.config.hypervisor.default_vcpus":  strconv.FormatUint(guestCPU/1000, 10),
		"io.katacontainers.config.hypervisor.default_memory": strconv.FormatUint(guestMemory/(1<<20), 10),
	}
	plan.HostConfig.CapAdd = append([]string{}, m.GuestCapabilities...)
	plan.HostConfig.StorageOpt = map[string]string{"size": strconv.FormatUint(m.Storage.OuterBytes, 10)}
	plan.HostConfig.Tmpfs = map[string]string{"/run": "rw,nosuid,nodev,size=134217728", "/tmp": "rw,nosuid,nodev,size=67108864"}
	if m.Storage.Block != nil {
		settings, _ := json.Marshal(GuestBlockSettings{Version: "runnerd09-guest-block-v1", Device: "/dev/neticora-execution", UUID: p.blockUUID(plan.Name), Bytes: m.Storage.Block.Bytes, UID: p.Base.RunnerUID})
		if m.Version == MultiBlockVersion {
			settings, _ = json.Marshal(GuestBlockSettings{Version: "runnerd09-guest-block-v2", Device: "/dev/neticora-execution", UUID: p.blockUUID(plan.Name), Bytes: m.Storage.Block.Bytes, UID: p.Base.RunnerUID, DNSServers: append([]string{}, m.GuestDNSServers...)})
		}
		plan.Config.Cmd = []string{"--block-storage", string(settings)}
		plan.HostConfig.Devices = []container.DeviceMapping{{PathOnHost: p.blockNode(plan.Name), PathInContainer: "/dev/neticora-execution", CgroupPermissions: "rw"}}
		delete(plan.HostConfig.Tmpfs, "/tmp")
	} else {
		plan.HostConfig.Mounts = append(plan.HostConfig.Mounts, mount.Mount{Type: mount.TypeBind, Source: filepath.Join(m.Storage.Graph.Root, plan.Name), Target: "/var/lib/docker", BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate}}, mount.Mount{Type: mount.TypeBind, Source: filepath.Join(m.Storage.Workspace.Root, plan.Name), Target: "/runner/_work", BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate}})
	}

	plan.HostConfig.Mounts = append(plan.HostConfig.Mounts, mount.Mount{Type: mount.TypeBind, Source: filepath.Join(p.HealthRoot(), plan.Name), Target: "/run/neticora-health", ReadOnly: false, BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate}})
	return plan, nil
}

// Probe verifies the actual bound engine in addition to local tuple hashes.
func (p *Profile) Probe(ctx context.Context, e *dockerengine.Engine) error {
	if err := p.RequireLaunchStorage(); err != nil {
		return err
	}
	if p.ObserverSocket != "" {
		return p.remote(ctx, "check", "", dockerengine.Plan{})
	}
	if p.Check(time.Now()) != nil {
		return ErrQualification
	}
	if p.Manifest.Version == MultiBlockVersion {
		if err := e.CheckKataHostCgroupDriver(ctx); err != nil {
			return err
		}
	}
	return e.CheckKataTuple(ctx, p.Manifest.RuntimeSelector, p.Manifest.DockerVersion, p.Manifest.Storage.DockerRoot, p.Manifest.ShimBinary, p.Manifest.RuntimeConfig, p.Manifest.DockerConfig, p.Manifest.Files[p.Manifest.DockerConfig])
}

// Expiry stops new admission, never authorized recovery of existing work.
func (p *Profile) RecoverProbe(ctx context.Context, e *dockerengine.Engine) error {
	if p.ObserverSocket != "" {
		return p.remote(ctx, "check-recovery", "", dockerengine.Plan{})
	}
	if p.layout() != nil {
		return ErrQualification
	}
	if p.Manifest.Version == MultiBlockVersion {
		if err := e.CheckKataHostCgroupDriver(ctx); err != nil {
			return err
		}
	}
	return e.CheckKataTuple(ctx, p.Manifest.RuntimeSelector, p.Manifest.DockerVersion, p.Manifest.Storage.DockerRoot, p.Manifest.ShimBinary, p.Manifest.RuntimeConfig, p.Manifest.DockerConfig, p.Manifest.Files[p.Manifest.DockerConfig])
}

func validRuntimeSelector(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}
