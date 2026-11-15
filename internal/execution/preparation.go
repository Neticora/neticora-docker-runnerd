package execution

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/executionstorage"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

type PreparationCheck struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}
type PreparationReport struct {
	Version            string                 `json:"verifierVersion"`
	ConfigurationValid bool                   `json:"configurationValid"`
	QualificationReady bool                   `json:"qualificationReady"`
	AdmissionEnabled   bool                   `json:"admissionEnabled"`
	WritesPerformed    bool                   `json:"writesPerformed"`
	JournalOpened      bool                   `json:"journalOpened"`
	InstallationID     string                 `json:"installationId,omitempty"`
	Identity           *protocol.HostIdentity `json:"identity,omitempty"`
	EndpointIdentity   string                 `json:"endpointIdentity,omitempty"`
	PolicyGeneration   string                 `json:"policyGeneration,omitempty"`
	PolicySha256       string                 `json:"policySha256,omitempty"`
	ConfigSha256       string                 `json:"configurationSha256"`
	CapabilitySha256   string                 `json:"capabilitiesSha256,omitempty"`
	Checks             []PreparationCheck     `json:"checks"`
}

// PrepareExecution only reads protected configuration/trust and probes the
// original Docker peer. It never opens a journal, a mutating engine, platform
// transport, bootstrap directory, signing authority or execution controller.
func PrepareExecution(ctx context.Context, raw []byte, now time.Time) PreparationReport {
	digest := sha256.Sum256(raw)
	out := PreparationReport{Version: Version(), ConfigSha256: hex.EncodeToString(digest[:]), Checks: []PreparationCheck{}}
	check := func(name string, ok bool, detail string) {
		state := "FAIL"
		if ok {
			state = "PASS"
		}
		out.Checks = append(out.Checks, PreparationCheck{Name: name, State: state, Detail: detail})
	}
	candidate, err := config.ParsePreparation(raw)
	if err != nil {
		check("inactive-configuration", false, "Complete configuration must validate with execution.enabled=false; installed configuration is unchanged.")
		return out
	}
	check("inactive-configuration", true, "Complete paths, PID limit, repository, trust timestamp and separation guards validated; activation remains disabled.")
	credentials, key, err := ReadCredentials(candidate.CredentialFile)
	if err != nil {
		check("identity", false, "Original protected installation credentials unavailable or invalid.")
		return out
	}
	defer clear(key)
	out.InstallationID = credentials.InstallationID
	out.Identity = &credentials.Identity
	out.EndpointIdentity = credentials.EndpointIdentity
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		check("identity", false, "Invalid Ed25519 public key.")
		return out
	}
	fingerprint := sha256.Sum256(der)
	binding := candidate.Connection
	if binding == nil || binding.TenantID != credentials.TenantID || credentials.InstallationID != "enrollment:"+binding.EnrollmentRequestID || binding.PublicKeyFingerprint != hex.EncodeToString(fingerprint[:]) {
		check("identity", false, "Original tenant and public-key connection binding required.")
		return out
	}
	check("identity", true, "Original key, installation, tenant and session retained; no enrollment or key creation.")
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != credentials.BootID {
		check("boot-continuity", false, "Original boot differs; separately authorized recovery required.")
		return out
	}
	check("boot-continuity", true, "Original boot retained.")
	x := candidate.Execution
	policyRaw, err := hostfs.ReadPrivate(x.PolicyFile, 65536)
	if err != nil {
		check("local-policy", false, "Protected local execution policy missing or unreadable.")
		return out
	}
	policy, err := standardlinux.ParsePolicy(policyRaw, nil)
	if err != nil || policy.UID() != os.Geteuid() || os.Geteuid() == 0 {
		check("local-policy", false, "Policy must validate for the nonroot effective service account.")
		return out
	}
	parsed, err := protocol.DecodeCustomerManagedPolicy(policyRaw)
	if err != nil || !slices.Contains(parsed.AllowedTenantIds, credentials.TenantID) || !slices.Contains(parsed.AllowedPoolIds, binding.RunnerDeploymentID) || !slices.Contains(parsed.AllowedProfiles, "standard-linux-v1") || !slices.Contains(parsed.AllowedTrustClasses, "trusted") {
		check("local-policy", false, "Exact tenant, pool, Standard profile and trusted workload scope required.")
		return out
	}
	canonical, err := protocol.CanonicalizeJSON(policyRaw)
	if err != nil {
		check("local-policy", false, "Policy canonicalization failed.")
		return out
	}
	policyHash := sha256.Sum256(canonical)
	out.PolicySha256 = hex.EncodeToString(policyHash[:])
	out.PolicyGeneration = policy.Generation()
	check("local-policy", true, "Schema, generation, nonzero ceilings and original tenant/pool authorization validated; no policy installed.")
	capsRaw, err := hostfs.ReadPrivate(x.CapabilitiesFile, 65536)
	if err != nil {
		check("capabilities", false, "Independently reviewed capability file is missing; hardware totals cannot replace it.")
		return out
	}
	caps, err := protocol.DecodeHostCapabilities(capsRaw)
	if err != nil || caps.EndpointIdentity != credentials.EndpointIdentity || caps.Host.Os != "linux" || caps.Engine.Os != "linux" || caps.Host.Architecture != "amd64" || caps.Engine.Architecture != "amd64" || caps.DockerBuild || caps.HardStorageLimit || !slices.Contains(caps.Profiles, "standard-linux-v1") {
		check("capabilities", false, "Current controller supports the explicit trusted process-only Linux/amd64 soft-storage tuple only.")
		return out
	}
	for _, value := range []string{caps.Capacity.CpuMillis, caps.Capacity.MemoryBytes, caps.Capacity.StorageBytes, caps.Capacity.Slots} {
		if value == "0" {
			check("capabilities", false, "Qualified capacity must be separately established, never copied from raw hardware totals.")
			return out
		}
	}
	canonical, err = protocol.CanonicalizeJSON(capsRaw)
	if err != nil {
		check("capabilities", false, "Capability canonicalization failed.")
		return out
	}
	capsHash := sha256.Sum256(canonical)
	out.CapabilitySha256 = hex.EncodeToString(capsHash[:])
	check("capabilities", true, "Proposed capability shape is compatible; independent acceptance remains required.")
	engine, err := dockerengine.OpenReadOnly(candidate.RuntimeEndpoint, credentials.InstallationID, func() {})
	if err != nil {
		check("runtime-continuity", false, "Read-only Docker observer unavailable.")
		return out
	}
	defer engine.Close()
	endpoint, err := engine.Probe(ctx)
	if err != nil || endpoint != credentials.EndpointIdentity {
		check("runtime-continuity", false, "Original Docker peer must match; no restart or adoption attempted.")
		return out
	}
	check("runtime-continuity", true, "Original authenticated Docker peer observed read-only.")
	provisioned, err := time.Parse(time.RFC3339Nano, x.TrustProvisionedAt)
	if err != nil {
		check("image-trust", false, "Invalid trust provisioning time.")
		return out
	}
	verifier := standardlinux.ImageVerifier{RootDirectory: x.TrustRoots, BundleDirectory: x.ImageBundles, ProvisionedAt: provisioned}
	imageTrust := true
	for _, digest := range parsed.Images.AllowedDigests {
		if verifier.Verify(ctx, policy, x.ImageRepository, digest, now) != nil {
			imageTrust = false
		}
	}
	check("image-trust", imageTrust, "Existing offline Sigstore verifier checks exact allowed digest, issuer/subject, provisioned root/bundle and freshness; no pull or fallback.")
	storageReady := x.StorageRoot != "" && len(x.RuntimeStoragePaths) > 0
	minimum := x.MinRuntimeFreeBytes
	if minimum == 0 {
		minimum = 256 << 20
	}
	if storageReady {
		storageReady = (executionstorage.Manager{Path: x.StorageRoot}).Headroom(minimum) == nil
	}
	for _, path := range x.RuntimeStoragePaths {
		if backingHeadroom(path, minimum) != nil {
			storageReady = false
		}
	}
	check("disk-execution-storage", storageReady, "New disk-template work requires a private durable execution root and independently verified actual Docker/containerd backing paths with free bytes/inodes; no directories or daemon settings are changed.")
	out.ConfigurationValid = imageTrust && storageReady
	out.Checks = append(out.Checks, PreparationCheck{Name: "resource-enforcement", State: "NOT TESTED", Detail: "Soft-storage template is not a whole-host hard storage bound. CPU/memory/PID/storage/network/concurrency/runtime-duration evidence requires a separately approved disposable campaign."}, PreparationCheck{Name: "platform-qualification", State: "NOT TESTED", Detail: "No platform policy, qualification signature or acceptance is written by preparation."}, PreparationCheck{Name: "authoritative-recovery", State: "NOT TESTED", Detail: "Only the approved execution controller may establish its original journal/claim/receipt checkpoint; inventory alone never qualifies recovery."})
	return out
}
