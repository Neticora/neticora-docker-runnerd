//go:build linux && runnerd_qualification

package qualfixture

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/provision"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

type PrepareSpec struct {
	Version            string                `json:"version"`
	Bundle             provision.Bundle      `json:"bundle"`
	Manifest           katalinux.Manifest    `json:"manifest"`
	Binding            katalinux.LabBinding  `json:"binding"`
	HostIdentity       protocol.HostIdentity `json:"hostIdentity"`
	HostPublicKey      string                `json:"hostPublicKey"`
	BootstrapFile      string                `json:"bootstrapFile"`
	BootstrapExpiresAt string                `json:"bootstrapExpiresAt"`
}
type RoleFile struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	UID         int    `json:"uid"`
	SHA256      string `json:"sha256"`
}
type PlanReceipt struct {
	Version                string     `json:"version"`
	CaseID                 string     `json:"caseId"`
	AuthorityPin           string     `json:"authorityPin"`
	ProfileVersion         string     `json:"profileVersion"`
	Qualified              bool       `json:"qualified"`
	ProductionAdmission    bool       `json:"productionAdmission"`
	RoleFiles              []RoleFile `json:"roleFiles"`
	ExistingCredentialFile string     `json:"existingCredentialFile"`
	HostPublicKeySHA256    string     `json:"hostPublicKeySha256"`
	OperatorOnly           []string   `json:"operatorOnly"`
}

func jsonBytes(v any) []byte    { raw, _ := json.MarshalIndent(v, "", "  "); return append(raw, '\n') }
func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func privateWrite(root, name string, data []byte) error {
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	file.Close()
	if err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
func hashed(schema string, value any) ([]byte, error) {
	raw, _ := json.Marshal(value)
	hash, err := protocol.PayloadHashJSON(schema, raw)
	if err != nil {
		return nil, err
	}
	var fields map[string]any
	json.Unmarshal(raw, &fields)
	key := "payloadHash"
	if schema == "ExecutionSpec" {
		key = "specHash"
	}
	fields[key] = hash
	message, err := protocol.EncodeValidated(schema, fields)
	if err != nil {
		return nil, err
	}
	return message.Bytes(), nil
}

// Prepare runs on the operator workstation. It creates separate ephemeral lab,
// TLS and image authorities; the role manifest never copies their private keys.
// The VM-generated host public identity is input, never an exported private key.
func Prepare(spec PrepareSpec, output string) (PlanReceipt, error) {
	var receipt PlanReceipt
	if _, err := provision.Parse(jsonBytes(spec.Bundle)); err != nil {
		return receipt, err
	}
	if _, err := os.Lstat("/etc/neticora-runnerd-lab"); err == nil {
		return receipt, ErrFixture
	}
	if spec.Version != "runnerd09-prepare-v1" || spec.Manifest.Qualified || len(spec.Manifest.Acceptance) != 0 || spec.Manifest.Version != katalinux.MultiBlockVersion || spec.HostIdentity.HostId != spec.Binding.HostID || spec.Binding.ControlPlaneURL != spec.Bundle.Daemon.ControlPlaneURL || spec.Binding.Repository != spec.Bundle.Daemon.Execution.Repository || spec.Binding.ServiceUID != spec.Bundle.Observer.ServiceUID {
		return receipt, ErrFixture
	}
	if !filepath.IsAbs(output) || filepath.Clean(output) != output || hostfs.CheckAncestors(filepath.Dir(output)) != nil {
		return receipt, fmt.Errorf("%w: protected output layout", ErrFixture)
	}
	if err := os.Mkdir(output, 0700); err != nil {
		return receipt, err
	}
	b := spec.Bundle
	x := b.Daemon.Execution
	now := time.Now().UTC().Truncate(time.Millisecond)
	until := now.Add(time.Hour)
	m := spec.Manifest
	m.Qualified = false
	m.Acceptance = nil
	m.VerifiedAt = now.Format("2006-01-02T15:04:05.000Z")
	m.ExpiresAt = until.Format("2006-01-02T15:04:05.000Z")
	if x.CustomCAFile == "" || m.Files == nil || m.ObserverConfig == "" || x.ImageRepository != m.ImageRepository {
		return receipt, ErrFixture
	}
	ca, server, key, err := fixtureTLS(spec.Binding.ControlPlaneURL, now, until)
	if err != nil {
		return receipt, err
	}
	for name, data := range map[string][]byte{"operator/tls-cert.pem": server, "operator/tls-key.pem": key} {
		if err = privateWrite(output, name, data); err != nil {
			return receipt, err
		}
	}
	if err = os.Mkdir(filepath.Join(output, "operator/fixture-state"), 0700); err != nil {
		return receipt, err
	}
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return receipt, err
	}
	defer clear(signer)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	receipt.AuthorityPin = digest(der)
	private, _ := x509.MarshalPKCS8PrivateKey(signer)
	if err = privateWrite(output, "operator/lab-authority-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})); err != nil {
		return receipt, err
	}
	clear(private)
	imageKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return receipt, err
	}
	imageDer, _ := x509.MarshalPKIXPublicKey(&imageKey.PublicKey)
	rootID := "runnerd09-lab-image"
	issuer := "https://runnerd09.invalid/lab/" + spec.Binding.CaseID
	subject := "runnerd09-lab:" + spec.Binding.CaseID
	rootBytes := jsonBytes(map[string]any{"version": "neticora-image-key-v1", "rootId": rootID, "rootVersion": "1", "issuer": issuer, "subject": subject, "validUntil": until.Format("2006-01-02T15:04:05.000Z"), "publicKeyPem": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: imageDer}))})
	payload := jsonBytes(map[string]any{"critical": map[string]any{"type": "cosign container image signature", "identity": map[string]any{"docker-reference": m.ImageRepository}, "image": map[string]any{"docker-manifest-digest": m.ImageDigest}}})
	hash := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, imageKey, hash[:])
	if err != nil {
		return receipt, err
	}
	imageBundle := jsonBytes([]any{map[string]any{"payload": base64.StdEncoding.EncodeToString(payload), "base64Signature": base64.StdEncoding.EncodeToString(signature)}})
	observerBytes := jsonBytes(b.Observer)
	m.Files[m.ObserverConfig] = digest(observerBytes)
	profileID, err := katalinux.ProfileID(m)
	if err != nil {
		return receipt, err
	}
	receipt.ProfileVersion = profileID
	x.TrustProvisionedAt = now.Format("2006-01-02T15:04:05.000Z")
	if _, err = provision.Parse(jsonBytes(b)); err != nil {
		return receipt, err
	}
	policy := map[string]any{"schemaVersion": "1.1", "generation": "1", "allowedTenantIds": []string{spec.Binding.TenantID}, "allowedPoolIds": []string{spec.Binding.PoolID}, "allowedProfiles": []string{profileID}, "allowedTrustClasses": []string{"trusted"}, "limits": m.Budget.Effective, "maxConcurrentExecutions": "1", "images": map[string]any{"requireSignature": true, "allowedDigests": []string{m.ImageDigest}, "trustRootId": rootID, "trustRootVersion": "1", "trustRootSha256": digest(rootBytes), "trustedIssuer": issuer, "trustedSubject": subject, "trustExpiresAt": until.Format("2006-01-02T15:04:05.000Z"), "maxOfflineAgeSeconds": 3600}, "transport": map[string]any{"proxyUrl": nil, "customCaSha256": digest(ca), "maxClockSkewSeconds": 60}, "onReload": "new-admissions-only", "restrictions": map[string]any{"runnerUid": b.Observer.ServiceUID, "allowRunnerSudo": false, "hostManagementAccess": false, "hostSshAgent": false, "dockerRestartPolicy": "no"}, "networkOwnership": "customer"}
	policyBytes := jsonBytes(policy)
	if _, err = protocol.DecodeCustomerManagedPolicy(policyBytes); err != nil {
		return receipt, err
	}
	capabilities := map[string]any{"host": map[string]string{"os": "linux", "architecture": "amd64", "build": "isolated qualification fixture"}, "engine": map[string]string{"os": "linux", "architecture": "amd64", "build": m.DockerVersion}, "endpointIdentity": m.EndpointIdentity, "runtimeVersion": m.KataVersion, "configurationGeneration": m.ConfigurationGeneration, "probeGeneration": "1", "observedAt": now.Format("2006-01-02T15:04:05.000Z"), "profiles": []string{profileID}, "dockerBuild": true, "hardStorageLimit": true, "capacity": m.Budget.Effective, "supportedImageFamilies": []string{"linux"}, "runtimeMechanism": "kata-runtime-rs-qemu"}
	capBytes := jsonBytes(capabilities)
	if _, err = protocol.DecodeHostCapabilities(capBytes); err != nil {
		return receipt, err
	}
	daemonBytes := jsonBytes(b.Daemon)
	binding := spec.Binding
	binding.DaemonConfigSHA256 = digest(daemonBytes)
	binding.ObserverConfigSHA256 = digest(observerBytes)
	binding.PolicySHA256 = digest(policyBytes)
	binding.CapabilitiesSHA256 = digest(capBytes)
	envelope, err := katalinux.SignLabEnvelope(katalinux.LabEnvelope{Version: katalinux.LabEnvelopeVersion, Manifest: m, Binding: binding, IssuedAt: now.Format("2006-01-02T15:04:05.000Z"), ExpiresAt: until.Format("2006-01-02T15:04:05.000Z")}, signer)
	if err != nil {
		return receipt, err
	}
	if err = katalinux.ValidateLabPlan(envelope, public, receipt.AuthorityPin, x.Kata.EvidenceDirectory, b.Daemon.StateDir, standardlinux.Settings{ImageRepository: m.ImageRepository, NetworkID: x.NetworkID, BootstrapRoot: x.BootstrapRoot, RunnerUID: b.Observer.ServiceUID, PidsLimit: x.PidsLimit}); err != nil {
		return receipt, err
	}
	role := func(source, destination string, uid int, data []byte) error {
		if err := privateWrite(output, source, data); err != nil {
			return err
		}
		receipt.RoleFiles = append(receipt.RoleFiles, RoleFile{source, destination, uid, digest(data)})
		return nil
	}
	for _, item := range []struct {
		source, destination string
		data                []byte
	}{{"client/daemon.json", "", daemonBytes}, {"client/policy.json", x.PolicyFile, policyBytes}, {"client/capabilities.json", x.CapabilitiesFile, capBytes}, {"client/profile.json", x.Kata.ProfileFile, jsonBytes(envelope)}, {"client/lab-public.pem", x.Kata.PublicKeyFile, public}, {"client/fixture-ca.pem", x.CustomCAFile, ca}, {"client/image-root.json", filepath.Join(x.TrustRoots, rootID+"-1.json"), rootBytes}, {"client/image-bundle.json", filepath.Join(x.ImageBundles, strings.TrimPrefix(m.ImageDigest, "sha256:")+".sigstore.json"), imageBundle}} {
		if item.source == "client/daemon.json" {
			item.destination = filepath.Join(filepath.Dir(x.PolicyFile), "config.json")
		}
		if err = role(item.source, item.destination, b.Observer.ServiceUID, item.data); err != nil {
			return receipt, err
		}
	}
	for _, item := range []struct {
		source, destination string
		data                []byte
	}{{"observer/config.json", m.ObserverConfig, observerBytes}, {"observer/lab-public.pem", b.Observer.PublicKeyFile, public}, {"observer/profile.json", filepath.Join(b.Observer.ProfileDirectory, profileID+".json"), jsonBytes(envelope)}} {
		if err = role(item.source, item.destination, 0, item.data); err != nil {
			return receipt, err
		}
	}
	for _, item := range []struct {
		source, destination string
		uid                 int
	}{{"client/binding.json", filepath.Join(filepath.Dir(x.PolicyFile), "binding.json"), b.Observer.ServiceUID}, {"observer/binding.json", filepath.Join(filepath.Dir(m.ObserverConfig), "binding.json"), 0}} {
		if err = role(item.source, item.destination, item.uid, jsonBytes(binding)); err != nil {
			return receipt, err
		}
	}
	start := protocol.StartCommand{CommandId: "start-" + binding.CaseID, Generation: "1", Kind: "start", PayloadHash: strings.Repeat("0", 64), Spec: protocol.ExecutionSpec{ExecutionId: "execution-" + binding.CaseID, AttemptId: "attempt-" + binding.CaseID, Generation: "1", SpecHash: strings.Repeat("0", 64), AuthorizationExpiresAt: until.Format("2006-01-02T15:04:05.000Z"), PolicyGeneration: "1", PoolId: binding.PoolID, ProfileVersion: profileID, CompatibilityRecordId: binding.InstallationID, ImageDigest: m.ImageDigest, TemplateVersion: katalinux.BlockTemplate, IsolationProfile: "isolated", DockerBuild: true, TrustClass: "trusted", Provider: "github", ExecutionBackend: "customer-host", RuntimeEngine: "docker", HostPlatform: protocol.Platform{Os: "linux", Architecture: "amd64", Build: "runnerd09-lab-candidate"}, RunnerPlatform: protocol.Platform{Os: "linux", Architecture: "amd64", Build: "runnerd09-lab-candidate"}, Resources: m.Budget.Effective}}
	specBytes, err := hashed("ExecutionSpec", start.Spec)
	if err != nil {
		return receipt, err
	}
	json.Unmarshal(specBytes, &start.Spec)
	commandBytes, err := hashed("HostCommand", start)
	if err != nil {
		return receipt, err
	}
	json.Unmarshal(commandBytes, &start)
	cleanupBytes, err := hashed("HostCommand", protocol.ControlCommand{Kind: "cleanup", CommandId: "cleanup-" + binding.CaseID, ExecutionId: start.Spec.ExecutionId, Generation: "1", PayloadHash: strings.Repeat("0", 64)})
	if err != nil {
		return receipt, err
	}
	var cleanup protocol.ControlCommand
	json.Unmarshal(cleanupBytes, &cleanup)
	fixture := Config{Version: "runnerd09-control-fixture-v1", CaseID: binding.CaseID, Identity: spec.HostIdentity, BootID: binding.BootID, EndpointIdentity: m.EndpointIdentity, HostPublicKey: spec.HostPublicKey, Start: start, Cleanup: cleanup, Policy: protocol.LocalPolicy{Generation: "1", AllowedProfiles: []string{profileID}, AllowedTrustClasses: []protocol.LocalPolicyAllowedTrustClasses{"trusted"}, Limits: m.Budget.Effective}, BootstrapFile: spec.BootstrapFile, BootstrapExpiresAt: spec.BootstrapExpiresAt}
	if err = privateWrite(output, "operator/fixture.json", jsonBytes(fixture)); err != nil {
		return receipt, err
	}
	if _, err = provision.Write(filepath.Join(output, "review-bundle"), b); err != nil {
		return receipt, err
	}
	if err = privateWrite(output, "review-bundle-input.json", jsonBytes(b)); err != nil {
		return receipt, err
	}
	receipt.Version = "runnerd09-lab-provision-v1"
	receipt.CaseID = binding.CaseID
	receipt.ExistingCredentialFile = b.Daemon.CredentialFile
	receipt.HostPublicKeySHA256 = digest([]byte(spec.HostPublicKey))
	receipt.OperatorOnly = []string{"operator/tls-key.pem", "operator/lab-authority-key.pem", "operator/fixture.json", "operator/fixture-state"}
	if err = privateWrite(output, "manifest.json", jsonBytes(receipt)); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func fixtureTLS(endpoint string, now, until time.Time) ([]byte, []byte, []byte, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, nil, nil, err
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || (!ip.IsLoopback() && !ip.IsPrivate()) {
		return nil, nil, nil, ErrFixture
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Runnerd09 isolated lab CA"}, NotBefore: now.Add(-time.Minute), NotAfter: until, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caRaw, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, _ = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Runnerd09 isolated control fixture"}, IPAddresses: []net.IP{ip}, NotBefore: now.Add(-time.Minute), NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certRaw, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caRaw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certRaw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), nil
}
