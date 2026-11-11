package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	"github.com/Neticora/neticora-docker-runnerd/journal"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

// LoadPolicy retains the last complete immutable generation on invalid reload.
// Equal-generation replacements may not mutate the active snapshot.
type PolicyFile struct {
	path    string
	mu      sync.Mutex
	current *standardlinux.Policy
}

func NewPolicyFile(path string) (*PolicyFile, error) {
	p := &PolicyFile{path: path}
	if p.Get() == nil {
		return nil, ErrReconcile
	}
	return p, nil
}
func (p *PolicyFile) Get() *standardlinux.Policy {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, err := hostfs.ReadPrivate(p.path, 65536)
	if err != nil {
		return p.current
	}
	next, err := standardlinux.ParsePolicy(raw, p.current)
	if err == nil {
		p.current = next
	}
	return p.current
}

func Open(c config.Config, store *journal.SQLiteStore, policy *PolicyFile, drained func() bool) (*Controller, func(), error) {
	return openWithKataLoader(c, store, policy, drained, katalinux.Load)
}

type kataLoader func(string, string, string, string, standardlinux.Settings) (*katalinux.Profile, error)

// The public constructor always supplies the strict production loader. The
// separately tagged lab constructor supplies its independently scoped authority.
func openWithKataLoader(c config.Config, store *journal.SQLiteStore, policy *PolicyFile, drained func() bool, load kataLoader) (*Controller, func(), error) {
	x := c.Execution
	if x == nil || !x.Enabled || goruntime.GOOS != "linux" || goruntime.GOARCH != "amd64" || os.Geteuid() == 0 || policy.Get().UID() != os.Geteuid() {
		return nil, nil, ErrReconcile
	}
	credentials, key, err := ReadCredentials(c.CredentialFile)
	if err != nil {
		return nil, nil, err
	}
	bootID, bootErr := actualBootID()
	if bootErr != nil || credentials.BootID != bootID {
		clear(key)
		return nil, nil, agent.ErrRecoveryRequired
	}
	if err = hostfs.CheckAncestors(filepath.Dir(x.BootstrapRoot)); err != nil {
		return nil, nil, err
	}
	if err = os.Mkdir(x.BootstrapRoot, 0700); err != nil && !os.IsExist(err) {
		return nil, nil, ErrReconcile
	}
	for _, dir := range []string{x.KeysDirectory, x.BootstrapRoot} {
		r, e := hostfs.OpenState(dir)
		if e != nil {
			return nil, nil, e
		}
		_ = r.Close()
	}
	if err = volatileDirectory(x.BootstrapRoot); err != nil {
		return nil, nil, err
	}
	if err = persistentDirectory(x.KeysDirectory); err != nil {
		return nil, nil, err
	}
	raw, err := hostfs.ReadPrivate(x.CapabilitiesFile, 65536)
	if err != nil {
		return nil, nil, err
	}
	capabilities, err := protocol.DecodeHostCapabilities(raw)
	isolated := x.Kata != nil
	if err != nil || capabilities.DockerBuild != isolated || capabilities.HardStorageLimit != isolated || capabilities.EndpointIdentity != credentials.EndpointIdentity || capabilities.Host.Os != "linux" || capabilities.Engine.Os != "linux" {
		return nil, nil, ErrReconcile
	}
	var ca []byte
	caDigest := ""
	if x.CustomCAFile != "" {
		ca, err = hostfs.ReadPrivate(x.CustomCAFile, 1<<20)
		if err != nil {
			return nil, nil, err
		}
		hash := sha256.Sum256(ca)
		caDigest = hex.EncodeToString(hash[:])
	}
	client, err := transport.NewWithRoots(c.ControlPlaneURL, c.Timeout(), ca)
	if err != nil {
		return nil, nil, err
	}
	runtime, err := dockerengine.Open(c.RuntimeEndpoint, credentials.InstallationID, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = store.InvalidateRuntime(ctx)
	})
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	cleanup := func() { _ = runtime.Close(); client.Close(); clear(key) }
	provisioned, _ := time.Parse(time.RFC3339Nano, x.TrustProvisionedAt)
	verifier := standardlinux.ImageVerifier{RootDirectory: x.TrustRoots, BundleDirectory: x.ImageBundles, ProvisionedAt: provisioned}
	remote := &HostRemote{Client: client, Credentials: credentials, Key: key, Capabilities: capabilities, PolicyGeneration: func() string { return policy.Get().Generation() }, Version: Version()}
	remote.CheckTransport = func() error {
		req, e := http.NewRequest("GET", c.ControlPlaneURL, nil)
		if e != nil {
			return ErrReconcile
		}
		proxy, e := http.ProxyFromEnvironment(req)
		if e != nil {
			return ErrReconcile
		}
		actualProxy := ""
		if proxy != nil {
			if proxy.User != nil {
				return ErrReconcile
			}
			actualProxy = proxy.String()
		}
		skew, measured := client.ClockSkew()
		return policy.Get().Transport(actualProxy, caDigest, skew, measured)
	}
	controller := &Controller{Store: store, Runtime: runtime, Remote: remote, SigningKey: key, Scope: agent.StoreScope{InstallationID: credentials.InstallationID, TenantID: credentials.TenantID, HostID: credentials.Identity.HostId, SessionEpoch: credentials.Identity.SessionEpoch, EndpointIdentity: credentials.EndpointIdentity}, Authority: journal.Authority{TenantID: credentials.TenantID, HostID: credentials.Identity.HostId, SessionEpoch: credentials.Identity.SessionEpoch, EndpointIdentity: credentials.EndpointIdentity, KeyID: credentials.Identity.KeyId}, Profile: standardlinux.Settings{ImageRepository: x.ImageRepository, NetworkID: x.NetworkID, BootstrapRoot: x.BootstrapRoot, RunnerUID: os.Geteuid(), PidsLimit: x.PidsLimit}, Policy: policy.Get, VerifyImage: verifier.Verify, KeysDirectory: x.KeysDirectory, Organization: x.Organization, Pool: x.Pool, Drained: drained}
	controller.HostLimits = policy.Get().Limits()
	if x.Kata != nil {
		controller.Kata, err = load(x.Kata.ProfileFile, x.Kata.PublicKeyFile, x.Kata.EvidenceDirectory, c.StateDir, controller.Profile)
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		controller.Kata.ObserverSocket = x.Kata.ObserverSocket
		if err = hostfs.CheckAncestors(filepath.Dir(controller.Kata.HealthRoot())); err != nil {
			cleanup()
			return nil, nil, err
		}
		if err = os.Mkdir(controller.Kata.HealthRoot(), 0700); err != nil && !os.IsExist(err) {
			cleanup()
			return nil, nil, err
		}
		healthRoot, healthErr := hostfs.OpenState(controller.Kata.HealthRoot())
		if healthErr != nil {
			cleanup()
			return nil, nil, healthErr
		}
		_ = healthRoot.Close()
		if err = volatileDirectory(controller.Kata.HealthRoot()); err != nil {
			cleanup()
			return nil, nil, err
		}
		if controller.Kata.Manifest.ConfigurationGeneration != capabilities.ConfigurationGeneration || controller.Kata.Manifest.EndpointIdentity != credentials.EndpointIdentity || capabilities.RuntimeMechanism != "kata-runtime-rs-qemu" || !slices.Contains(capabilities.Profiles, controller.Kata.ID) {
			cleanup()
			return nil, nil, katalinux.ErrQualification
		}
		if err = controller.Kata.ProtectPaths(c.CredentialFile, x.KeysDirectory, x.PolicyFile, x.CapabilitiesFile, x.TrustRoots, x.ImageBundles, x.CustomCAFile, x.Kata.ProfileFile, x.Kata.PublicKeyFile, x.Kata.ObserverSocket); err != nil {
			cleanup()
			return nil, nil, err
		}
		if err = controller.Kata.RecoverProbe(context.Background(), runtime); err != nil {
			cleanup()
			return nil, nil, err
		}
		controller.HostLimits.Slots = min(controller.HostLimits.Slots, controller.Kata.MaxConcurrentAllocations())
	}
	capacity := capabilities.Capacity
	ceilings := []*uint64{&controller.HostLimits.CPUMillis, &controller.HostLimits.MemoryBytes, &controller.HostLimits.StorageBytes, &controller.HostLimits.Slots}
	for i, value := range []string{capacity.CpuMillis, capacity.MemoryBytes, capacity.StorageBytes, capacity.Slots} {
		limit, e := strconv.ParseUint(value, 10, 64)
		if e != nil || limit == 0 {
			cleanup()
			return nil, nil, ErrReconcile
		}
		*ceilings[i] = min(*ceilings[i], limit)
	}
	controller.Repository = x.Repository
	controller.MinRuntimeFreeBytes = x.MinRuntimeFreeBytes
	return controller, cleanup, nil
}
