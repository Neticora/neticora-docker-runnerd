package execution

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

var ErrQualification = errors.New("current independently signed execution qualification required")

func sameQualifiedTemplate(a, b protocol.ExecutionSpec) bool {
	for _, spec := range []*protocol.ExecutionSpec{&a, &b} {
		spec.ExecutionId = ""
		spec.AttemptId = ""
		spec.Generation = ""
		spec.AuthorizationExpiresAt = ""
		spec.SpecHash = ""
	}
	x, e1 := json.Marshal(a)
	y, e2 := json.Marshal(b)
	return e1 == nil && e2 == nil && bytes.Equal(x, y)
}

// Qualification reads the same operator-signed manifest used by platform dispatch.
// Its public key must be independently provisioned, never taken from the artifact.
// This proves acceptance of the exact version/tuple, not platform admission.
func Qualification(c config.Config, credentials Credentials, now time.Time) (protocol.ExecutionSpec, error) {
	x := c.Execution
	if x == nil || x.RunnerSize == "" {
		return protocol.ExecutionSpec{}, ErrQualification
	}
	raw, e := hostfs.ReadPrivate(x.QualificationFile, 65536)
	if e != nil {
		return protocol.ExecutionSpec{}, ErrQualification
	}
	key, e := hostfs.ReadPrivate(x.QualificationPublicKeyFile, 16384)
	if e != nil {
		return protocol.ExecutionSpec{}, ErrQualification
	}
	caps, e := hostfs.ReadPrivate(x.CapabilitiesFile, 65536)
	if e != nil {
		return protocol.ExecutionSpec{}, ErrQualification
	}
	policy, e := hostfs.ReadPrivate(x.PolicyFile, 65536)
	if e != nil {
		return protocol.ExecutionSpec{}, ErrQualification
	}
	return verifyQualification(raw, key, caps, policy, c, credentials, now)
}

func verifyQualification(raw, key, caps, policy []byte, c config.Config, credentials Credentials, now time.Time) (protocol.ExecutionSpec, error) {
	var zero protocol.ExecutionSpec
	canonical, e := protocol.CanonicalizeJSON(raw)
	if e != nil {
		return zero, ErrQualification
	}
	var signed struct {
		Manifest  json.RawMessage `json:"manifest"`
		Signature string          `json:"signature"`
	}
	d := json.NewDecoder(bytes.NewReader(canonical))
	d.DisallowUnknownFields()
	if d.Decode(&signed) != nil {
		return zero, ErrQualification
	}
	block, rest := pem.Decode(key)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return zero, ErrQualification
	}
	parsed, e := x509.ParsePKIXPublicKey(block.Bytes)
	pub, ok := parsed.(ed25519.PublicKey)
	sig, sigErr := base64.RawURLEncoding.DecodeString(signed.Signature)
	manifest, canonErr := protocol.CanonicalizeJSON(signed.Manifest)
	if e != nil || !ok || sigErr != nil || base64.RawURLEncoding.EncodeToString(sig) != signed.Signature || canonErr != nil || !ed25519.Verify(pub, manifest, sig) {
		return zero, ErrQualification
	}
	var m struct {
		Version                        string                     `json:"version"`
		StorageEnforcement             string                     `json:"storageEnforcement"`
		TenantID                       string                     `json:"tenantId"`
		HostID                         string                     `json:"hostId"`
		SessionEpoch                   string                     `json:"sessionEpoch"`
		EndpointIdentity               string                     `json:"endpointIdentity"`
		AgentVersion                   string                     `json:"agentVersion"`
		ExpiresAt                      string                     `json:"expiresAt"`
		VerifiedAt                     string                     `json:"verifiedAt"`
		CapabilitiesHash               string                     `json:"capabilitiesHash"`
		Policy                         json.RawMessage            `json:"policy"`
		Specs                          map[string]json.RawMessage `json:"specs"`
		ImageVerificationReference     string                     `json:"imageVerificationReference"`
		ProviderQualificationReference string                     `json:"providerQualificationReference"`
	}
	if json.Unmarshal(manifest, &m) != nil || c.Connection == nil || c.Execution == nil {
		return zero, ErrQualification
	}
	expires, e1 := time.Parse(time.RFC3339Nano, m.ExpiresAt)
	verified, e2 := time.Parse(time.RFC3339Nano, m.VerifiedAt)
	if m.Version != "runnerd07-qualification-v1" || m.StorageEnforcement != "soft" || e1 != nil || e2 != nil || !expires.After(now) || verified.After(now) || m.TenantID != credentials.TenantID || m.HostID != credentials.Identity.HostId || m.SessionEpoch != credentials.Identity.SessionEpoch || m.EndpointIdentity != credentials.EndpointIdentity || m.AgentVersion != Version() || m.ImageVerificationReference == "" || m.ProviderQualificationReference == "" {
		return zero, ErrQualification
	}
	var capability map[string]json.RawMessage
	if json.Unmarshal(caps, &capability) != nil {
		return zero, ErrQualification
	}
	capabilities, e := protocol.DecodeHostCapabilities(caps)
	if e != nil || capabilities.HardStorageLimit || capabilities.DockerBuild || capabilities.EndpointIdentity != credentials.EndpointIdentity {
		return zero, ErrQualification
	}
	delete(capability, "observedAt")
	delete(capability, "probeGeneration")
	stable, _ := json.Marshal(capability)
	stable, e = protocol.CanonicalizeJSON(stable)
	h := sha256.Sum256(stable)
	localPolicy, e3 := protocol.DecodeCustomerManagedPolicy(policy)
	local, e4 := protocol.CanonicalizeJSON(policy)
	accepted, e5 := protocol.CanonicalizeJSON(m.Policy)
	trustExpiry, e6 := time.Parse(time.RFC3339Nano, localPolicy.Images.TrustExpiresAt)
	if e != nil || hex.EncodeToString(h[:]) != m.CapabilitiesHash || e3 != nil || e4 != nil || e5 != nil || !bytes.Equal(local, accepted) || e6 != nil || !trustExpiry.After(now) || now.Sub(verified).Seconds() > float64(localPolicy.Images.MaxOfflineAgeSeconds) {
		return zero, ErrQualification
	}
	spec, e := protocol.DecodeExecutionSpec(m.Specs[c.Execution.RunnerSize])
	if e != nil || spec.PoolId != c.Connection.RunnerDeploymentID || spec.PolicyGeneration != localPolicy.Generation || spec.TemplateVersion != "linux-github-disk-v1" || spec.ProfileVersion != "standard-linux-v1" || spec.TrustClass != "trusted" || spec.DockerBuild || spec.Provider != "github" || spec.RuntimeEngine != "docker" || spec.ExecutionBackend != "customer-host" || c.Execution.StorageRoot == "" {
		return zero, ErrQualification
	}
	if !slices.Contains(localPolicy.AllowedTenantIds, credentials.TenantID) || !slices.Contains(localPolicy.AllowedPoolIds, spec.PoolId) || !slices.Contains(localPolicy.AllowedProfiles, spec.ProfileVersion) || !slices.Contains(localPolicy.Images.AllowedDigests, spec.ImageDigest) || spec.HostPlatform.Os != "linux" || spec.HostPlatform.Architecture != "amd64" || spec.HostPlatform.Build != capabilities.Host.Build || spec.RunnerPlatform.Os != "linux" || spec.RunnerPlatform.Architecture != "amd64" {
		return zero, ErrQualification
	}
	requested := []string{spec.Resources.CpuMillis, spec.Resources.MemoryBytes, spec.Resources.StorageBytes, spec.Resources.Slots}
	ceilings := []string{localPolicy.Limits.CpuMillis, localPolicy.Limits.MemoryBytes, localPolicy.Limits.StorageBytes, localPolicy.Limits.Slots}
	physical := []string{capabilities.Capacity.CpuMillis, capabilities.Capacity.MemoryBytes, capabilities.Capacity.StorageBytes, capabilities.Capacity.Slots}
	for i, value := range requested {
		n, err := strconv.ParseUint(value, 10, 64)
		ceiling, _ := strconv.ParseUint(ceilings[i], 10, 64)
		capacity, _ := strconv.ParseUint(physical[i], 10, 64)
		if err != nil || n == 0 || n > ceiling || n > capacity {
			return zero, ErrQualification
		}
	}
	return spec, nil
}
