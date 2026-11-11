//go:build linux && runnerd_qualification

package katalinux

// Lab envelopes are deliberately not production Signed artifacts. This entire
// loader/API is absent from ordinary builds; Load still rejects these bytes.
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
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

const LabEnvelopeVersion = "runnerd09-lab-authority-v1"

// The operator pins both the independent key hash and exact binding outside the
// supplied envelope. No tenant, endpoint, boot or configuration is inferred.
type LabBinding struct {
	CaseID               string `json:"caseId"`
	HostID               string `json:"hostId"`
	TenantID             string `json:"tenantId"`
	PoolID               string `json:"poolId"`
	Repository           string `json:"repository"`
	InstallationID       string `json:"installationId"`
	BootID               string `json:"bootId"`
	MachineUUID          string `json:"machineUuid"`
	ControlPlaneURL      string `json:"controlPlaneUrl"`
	ServiceUID           int    `json:"serviceUid"`
	DaemonConfigSHA256   string `json:"daemonConfigSha256"`
	ObserverConfigSHA256 string `json:"observerConfigSha256"`
	PolicySHA256         string `json:"policySha256"`
	CapabilitiesSHA256   string `json:"capabilitiesSha256"`
}

type LabEnvelope struct {
	Version   string     `json:"version"`
	Manifest  Manifest   `json:"manifest"`
	Binding   LabBinding `json:"binding"`
	IssuedAt  string     `json:"issuedAt"`
	ExpiresAt string     `json:"expiresAt"`
	Signature string     `json:"signature"`
}

func labMessage(e LabEnvelope) ([]byte, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, ErrQualification
	}
	delete(fields, "signature")
	raw, err = json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	return protocol.CanonicalizeJSON(raw)
}

// SignLabEnvelope never claims completed acceptance or production eligibility.
// The key belongs on the operator workstation, never the workload host.
func SignLabEnvelope(e LabEnvelope, key ed25519.PrivateKey) (LabEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize || e.Version != LabEnvelopeVersion || !validLabBinding(e.Binding) || e.Manifest.Qualified || len(e.Manifest.Acceptance) != 0 {
		return e, ErrQualification
	}
	message, err := labMessage(e)
	if err != nil {
		return e, err
	}
	e.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))
	return e, nil
}

// ValidateLabPlan performs signature/structure validation on the workstation;
// live machine, filesystem and runtime checks remain mandatory at execution.
func ValidateLabPlan(e LabEnvelope, public []byte, pin, evidence, journal string, base standardlinux.Settings) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = decodeLabProfile(raw, public, pin, e.Binding, evidence, journal, base, time.Now())
	return err
}

func validLabBinding(b LabBinding) bool {
	u, err := url.Parse(b.ControlPlaneURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/api/v1/runner-hosts" {
		return false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || (!ip.IsLoopback() && !ip.IsPrivate()) || u.Port() == "" {
		return false
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`).MatchString(b.CaseID) || b.InstallationID != "runnerd09-lab-"+b.CaseID || b.HostID != b.InstallationID || b.TenantID != b.InstallationID || b.PoolID != b.InstallationID || b.Repository == "" || b.BootID == "" || b.MachineUUID == "" || b.ServiceUID < 1 {
		return false
	}
	for _, value := range []string{b.DaemonConfigSHA256, b.ObserverConfigSHA256, b.PolicySHA256, b.CapabilitiesSHA256} {
		if len(value) != 64 {
			return false
		}
		if _, err := hex.DecodeString(value); err != nil {
			return false
		}
	}
	return true
}

func requireLabMachine(b LabBinding) error {
	if os.Getenv("RUNNERD09_LIVE_QUALIFICATION") != "1" {
		return ErrQualification
	}
	info, err := os.Lstat("/etc/neticora-runnerd-lab")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return ErrQualification
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return ErrQualification
	}
	if err = hostfs.CheckAncestors("/etc"); err != nil {
		return err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != b.BootID {
		return ErrQualification
	}
	// DMI is root-readable on the supported host. The authenticated root
	// observer independently enforces this binding on every request.
	if os.Geteuid() == 0 {
		uuid, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
		if err != nil || !strings.EqualFold(strings.TrimSpace(string(uuid)), b.MachineUUID) {
			return ErrQualification
		}
	}
	if os.Geteuid() != 0 && os.Geteuid() != b.ServiceUID {
		return ErrQualification
	}
	return nil
}

func decodeLabProfile(raw, public []byte, pin string, expected LabBinding, evidence, journal string, base standardlinux.Settings, now time.Time) (*Profile, error) {
	if len(raw) > 131072 || !validLabBinding(expected) {
		return nil, ErrQualification
	}
	if _, err := protocol.CanonicalizeJSON(raw); err != nil {
		return nil, ErrQualification
	}
	var envelope LabEnvelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || envelope.Version != LabEnvelopeVersion || envelope.Binding != expected || envelope.Manifest.Qualified || len(envelope.Manifest.Acceptance) != 0 || envelope.Manifest.Version != MultiBlockVersion {
		return nil, ErrQualification
	}
	block, rest := pem.Decode(public)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrQualification
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrQualification
	}
	pub, ok := key.(ed25519.PublicKey)
	hash := sha256.Sum256(block.Bytes)
	if !ok || hex.EncodeToString(hash[:]) != pin {
		return nil, ErrQualification
	}
	message, err := labMessage(envelope)
	var original map[string]json.RawMessage
	if json.Unmarshal(raw, &original) != nil || len(original) != 6 || original["signature"] == nil {
		return nil, ErrQualification
	}
	delete(original, "signature")
	originalRaw, _ := json.Marshal(original)
	originalMessage, originalErr := protocol.CanonicalizeJSON(originalRaw)
	signature, sigErr := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || originalErr != nil || !bytes.Equal(message, originalMessage) || sigErr != nil || base64.RawURLEncoding.EncodeToString(signature) != envelope.Signature || !ed25519.Verify(pub, message, signature) {
		return nil, ErrQualification
	}
	issued, err := time.Parse(time.RFC3339Nano, envelope.IssuedAt)
	expires, expiryErr := time.Parse(time.RFC3339Nano, envelope.ExpiresAt)
	profileExpiry, profileExpiryErr := time.Parse(time.RFC3339Nano, envelope.Manifest.ExpiresAt)
	if err != nil || expiryErr != nil || profileExpiryErr != nil || issued.After(now) || !expires.After(issued) || expires.Sub(issued) > 6*time.Hour || profileExpiry.After(expires) {
		return nil, ErrQualification
	}
	if base.RunnerUID != expected.ServiceUID || envelope.Manifest.ObserverConfig == "" || envelope.Manifest.Files[envelope.Manifest.ObserverConfig] != expected.ObserverConfigSHA256 {
		return nil, ErrQualification
	}
	id, err := ProfileID(envelope.Manifest)
	if err != nil {
		return nil, err
	}
	p := &Profile{Manifest: envelope.Manifest, ID: id, EvidenceDirectory: evidence, JournalDirectory: journal, Base: base}
	p.qualificationApproval = func() error {
		current, e := ProfileID(p.Manifest)
		if e != nil || current != id || p.Base.RunnerUID != expected.ServiceUID {
			return ErrQualification
		}
		return nil
	}
	if err = p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func LoadQualification(file, public, pin string, expected LabBinding, evidence, journal string, base standardlinux.Settings) (*Profile, error) {
	if requireLabMachine(expected) != nil {
		return nil, ErrQualification
	}
	raw, err := hostfs.ReadPrivate(file, 131072)
	if err != nil {
		return nil, err
	}
	key, err := hostfs.ReadPrivate(public, 16384)
	if err != nil {
		return nil, err
	}
	p, err := decodeLabProfile(raw, key, pin, expected, evidence, journal, base, time.Now())
	if err != nil {
		return nil, err
	}
	p.storageAuthority = public
	approval := p.qualificationApproval
	p.qualificationApproval = func() error {
		if requireLabMachine(expected) != nil {
			return ErrQualification
		}
		return approval()
	}
	if err = p.ProtectPaths(file, public); err != nil {
		return nil, err
	}
	return p, nil
}

func ServeQualificationObserver(ctx context.Context, file, pin string, binding LabBinding) error {
	if requireLabMachine(binding) != nil || digestFile(file, binding.ObserverConfigSHA256) != nil {
		return ErrQualification
	}
	return serveObserver(ctx, file, func(profile, public, evidence, journal string, base standardlinux.Settings) (*Profile, error) {
		return LoadQualification(profile, public, pin, binding, evidence, journal, base)
	})
}

// ValidateLabFiles prevents a config/policy/capability swap after signing.
func ValidateLabFiles(binding LabBinding, daemon, policy, capabilities string) error {
	for file, want := range map[string]string{daemon: binding.DaemonConfigSHA256, policy: binding.PolicySHA256, capabilities: binding.CapabilitiesSHA256} {
		raw, err := hostfs.ReadPrivate(filepath.Clean(file), 65536)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != want {
			return ErrQualification
		}
	}
	return nil
}
