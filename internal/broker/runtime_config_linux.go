//go:build linux

package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

type RuntimeConfig struct {
	Kata                    *KataConfig `json:"kata,omitempty"`
	Endpoint                string      `json:"endpoint"`
	PolicyFile              string      `json:"policyFile"`
	ImageRepository         string      `json:"imageRepository"`
	NetworkID               string      `json:"networkId"`
	BootstrapRoot           string      `json:"bootstrapRoot"`
	ControllerBootstrapRoot string      `json:"controllerBootstrapRoot"`
	TrustRoots              string      `json:"trustRoots"`
	ImageBundles            string      `json:"imageBundles"`
	TrustProvisionedAt      string      `json:"trustProvisionedAt"`
	PidsLimit               int64       `json:"pidsLimit"`
	Organization            string      `json:"organization"`
	Repository              string      `json:"repository"`
	Pool                    string      `json:"pool"`
	DisposalKeyFile         string      `json:"disposalKeyFile"`
	QualificationMarker     string      `json:"qualificationMarker"`
	QualificationFaultFile  string      `json:"qualificationFaultFile,omitempty"`
	BootRecoveryOnly        bool        `json:"bootRecoveryOnly,omitempty"`
}

func openRuntime(ctx context.Context, c Config, l *Ledger, key ed25519.PublicKey) (*physicalExecutor, ed25519.PrivateKey, func(), error) {
	noop := func() {}
	if c.Runtime == nil {
		return nil, nil, noop, nil
	}
	if !runtimeQualification {
		return nil, nil, noop, ErrRejected
	}
	x := c.Runtime
	raw, err := hostfs.ReadPrivate(x.QualificationMarker, MaxMessage)
	if err != nil {
		return nil, nil, noop, err
	}
	var marker struct {
		Purpose             string `json:"purpose"`
		InstallationID      string `json:"installationId"`
		HostID              string `json:"hostId"`
		Endpoint            string `json:"endpoint"`
		ExpiresAt           string `json:"expiresAt"`
		ProductionAdmission bool   `json:"productionAdmission"`
	}
	if decode(raw, &marker) != nil || marker.Purpose != "runnerd-phase-d-disposable" || marker.InstallationID != c.Scope.InstallationID || marker.HostID != c.Scope.HostID || marker.Endpoint != x.Endpoint || marker.ProductionAdmission {
		return nil, nil, noop, ErrRejected
	}
	expires, err := time.Parse(time.RFC3339Nano, marker.ExpiresAt)
	if err != nil || !time.Now().Before(expires) || expires.Sub(time.Now()) > time.Hour {
		return nil, nil, noop, ErrRejected
	}
	raw, err = hostfs.ReadPrivate(x.PolicyFile, MaxMessage)
	if err != nil {
		return nil, nil, noop, err
	}
	policy, err := standardlinux.ParsePolicy(raw, nil)
	if err != nil || policy.UID() != int(c.ControllerUID) {
		return nil, nil, noop, ErrRejected
	}
	provisioned, err := time.Parse(time.RFC3339Nano, x.TrustProvisionedAt)
	if err != nil {
		return nil, nil, noop, err
	}
	bootRaw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, nil, noop, err
	}
	boot := string(bytesTrimSpace(bootRaw))
	if len(boot) != 36 {
		return nil, nil, noop, ErrRejected
	}
	m, err := openHandoffs(l, x.ControllerBootstrapRoot, x.BootstrapRoot, int(c.ControllerUID), boot, x.Organization, x.Repository, x.Pool)
	if err != nil {
		return nil, nil, noop, err
	}
	engine, err := dockerengine.Open(x.Endpoint, c.Scope.InstallationID, nil)
	if err != nil {
		m.root.Close()
		m.source.Close()
		return nil, nil, noop, err
	}
	closeKata := func() {}
	closeAll := func() { closeKata(); _ = engine.Close(); m.root.Close(); m.source.Close() }
	endpoint, err := engine.Probe(ctx)
	if err != nil || (endpoint != c.Scope.EndpointIdentity && !x.BootRecoveryOnly) {
		closeAll()
		return nil, nil, noop, ErrRejected
	}
	privateRaw, err := hostfs.ReadPrivate(x.DisposalKeyFile, 16384)
	if err != nil {
		closeAll()
		return nil, nil, noop, err
	}
	defer clear(privateRaw)
	block, rest := pem.Decode(privateRaw)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		closeAll()
		return nil, nil, noop, ErrRejected
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		closeAll()
		return nil, nil, noop, err
	}
	private, ok := value.(ed25519.PrivateKey)
	if !ok || private.Public().(ed25519.PublicKey).Equal(key) {
		closeAll()
		return nil, nil, noop, ErrRejected
	}
	verifier := standardlinux.ImageVerifier{RootDirectory: x.TrustRoots, BundleDirectory: x.ImageBundles, ProvisionedAt: provisioned}
	e := &physicalExecutor{ledger: l, runtime: engine, key: key, scope: c.Scope, settings: standardlinux.Settings{ImageRepository: x.ImageRepository, NetworkID: x.NetworkID, BootstrapRoot: x.BootstrapRoot, RunnerUID: int(c.ControllerUID), PidsLimit: x.PidsLimit}, policy: policy, boot: boot, now: time.Now, handoffs: m,
		recoveryOnly: x.BootRecoveryOnly, runtimeEndpoint: endpoint,
		checkpoint: qualificationCheckpoint(x.QualificationFaultFile),
		verifyImage: func(ctx context.Context, s protocol.ExecutionSpec) error {
			if !time.Now().Before(expires) {
				return ErrRejected
			}
			return verifier.Verify(ctx, policy, x.ImageRepository, s.ImageDigest, time.Now())
		},
		guardMounts: func(_ context.Context, p dockerengine.Plan) error { return m.Prepare(p) }}
	if x.Kata != nil {
		if x.BootRecoveryOnly {
			closeAll()
			clear(private)
			return nil, nil, noop, ErrRejected
		}
		profile, loadErr := loadKata(c, *x.Kata, e.settings)
		if loadErr != nil {
			closeAll()
			clear(private)
			return nil, nil, noop, loadErr
		}
		if err = profile.ProtectPaths(c.StateDirectory, c.Socket, x.PolicyFile, x.TrustRoots, x.ImageBundles, x.DisposalKeyFile, x.QualificationMarker, x.QualificationFaultFile, x.ControllerBootstrapRoot, x.BootstrapRoot, profile.HealthRoot()); err != nil {
			closeAll()
			clear(private)
			return nil, nil, noop, err
		}
		release, claimErr := profile.ClaimBroker(c.Scope.InstallationID, c.Scope.HostID)
		if claimErr != nil {
			closeAll()
			clear(private)
			return nil, nil, noop, claimErr
		}
		closeKata = release
		if profile.Manifest.EndpointIdentity != endpoint || profile.Manifest.ImageRepository != x.ImageRepository {
			closeAll()
			clear(private)
			return nil, nil, noop, ErrRejected
		}
		if err = profile.RecoverProbe(ctx, engine); err != nil {
			closeAll()
			clear(private)
			return nil, nil, noop, err
		}
		if err = os.Mkdir(profile.HealthRoot(), 0700); err != nil && !os.IsExist(err) {
			closeAll()
			clear(private)
			return nil, nil, noop, err
		}
		health, healthErr := hostfs.OpenState(profile.HealthRoot())
		if healthErr != nil {
			closeAll()
			clear(private)
			return nil, nil, noop, healthErr
		}
		health.Close()
		e.kata = &protectedKata{profile: profile, engine: engine}
	}
	return e, private, func() { clear(private); closeAll() }, nil
}

func bytesTrimSpace(v []byte) []byte {
	for len(v) > 0 && (v[len(v)-1] == '\n' || v[len(v)-1] == '\r' || v[len(v)-1] == ' ') {
		v = v[:len(v)-1]
	}
	return v
}
