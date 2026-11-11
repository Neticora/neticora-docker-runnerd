//go:build linux && runnerd_qualification

package qualfixture_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/provision"
	"github.com/Neticora/neticora-docker-runnerd/internal/qualfixture"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

func prepareInputs(t *testing.T) (qualfixture.PrepareSpec, *fixture) {
	t.Helper()
	f := setup(t)
	base := "/var/lib/neticora-runnerd09-lab/config/fixture"
	client := base + "/client"
	root := base + "/observer"
	runtime := "/run/neticora-runnerd09-qualification/fixture"
	hash := strings.Repeat("a", 64)
	b := provision.Bundle{Version: "runnerd09-config-bundle-v1", Daemon: config.Config{ControlPlaneURL: "https://127.0.0.1:16443/api/v1/runner-hosts", StateDir: "/var/lib/neticora-runnerd09-lab/journal", CredentialFile: client + "/identity.json", RuntimeEndpoint: "unix:///run/runnerd09-docker.sock", RequestTimeoutSeconds: 15, Execution: &config.Execution{Enabled: true, Repository: "Neticora/neticora-alpha", Organization: "Neticora", Pool: f.config.Identity.HostId, ImageRepository: "127.0.0.1:5509/runnerd09/kata", NetworkID: hash, PolicyFile: client + "/policy.json", CapabilitiesFile: client + "/capabilities.json", CustomCAFile: client + "/ca.pem", KeysDirectory: client + "/keys", BootstrapRoot: runtime + "/bootstrap", TrustRoots: client + "/roots", ImageBundles: client + "/bundles", TrustProvisionedAt: time.Now().UTC().Format(time.RFC3339Nano), PidsLimit: 512, Kata: &config.Kata{ObserverSocket: runtime + "/observer/socket", ProfileFile: client + "/profile.json", PublicKeyFile: client + "/public.pem", EvidenceDirectory: "/var/lib/neticora-runnerd09-lab/evidence"}}}, Observer: katalinux.ObserverConfig{Socket: runtime + "/observer/socket", ServiceUID: 10001, ProfileDirectory: root + "/profiles", PublicKeyFile: root + "/public.pem", EvidenceDirectory: "/var/lib/neticora-runnerd09-lab/evidence", JournalDirectory: "/var/lib/neticora-runnerd09-lab/journal", RuntimeEndpoint: "unix:///run/runnerd09-docker.sock", InstallationID: f.config.Identity.HostId, HostID: f.config.Identity.HostId, NetworkID: hash, BootstrapRoot: runtime + "/bootstrap", PidsLimit: 512}}
	m := katalinux.Manifest{Version: katalinux.MultiBlockVersion, Qualified: false, GuestStorageDriver: "overlay2", RuntimeImplementation: "runtime-rs", Hypervisor: "qemu", EndpointIdentity: "docker-" + hash, ConfigurationGeneration: "1", HostKernel: "unit", DockerVersion: "unit", RuntimeSelector: "unit-kata", KataVersion: "unit", QEMUVersion: "unit", GuestKernelVersion: "unit", GuestImageVersion: "unit", ImageRepository: b.Daemon.Execution.ImageRepository, ImageDigest: "sha256:" + hash, QEMUBinary: "/tuple/qemu", ShimBinary: "/tuple/shim", DockerConfig: "/tuple/docker.json", ObserverConfig: root + "/config.json", RuntimeConfig: "/tuple/runtime.toml", HostOSFile: "/tuple/os-release", GuestKernel: "/tuple/kernel", GuestImage: "/tuple/rootfs", VMNamePrefix: "sandbox-", SandboxRoots: []string{"/tuple/runtime/sbs"}, GuestCapabilities: []string{"SETUID", "SETGID", "CHOWN", "SYS_ADMIN", "DAC_OVERRIDE"}, GuestDNSServers: []string{"192.0.2.53"}, SecurityReview: "Unit structural fixture; no live qualification", Files: map[string]string{}, Deadlines: katalinux.Deadlines{StartupSeconds: 90, HeartbeatSeconds: 30, TerminationSeconds: 30, ExecutionSeconds: 3600}, HostCgroup: &katalinux.HostCgroup{Method: "systemd-transient-slice-v1", SystemctlBinary: "/tuple/systemctl", BusctlBinary: "/tuple/busctl", PidsLimit: 512}}
	for _, path := range []string{m.QEMUBinary, m.ShimBinary, m.DockerConfig, m.ObserverConfig, m.RuntimeConfig, m.HostOSFile, m.GuestKernel, m.GuestImage, m.HostCgroup.SystemctlBinary, m.HostCgroup.BusctlBinary, "/tuple/formatter", "/etc/mke2fs.conf"} {
		m.Files[path] = hash
	}
	m.Storage = katalinux.Storage{Block: &katalinux.BlockStorage{Method: "preallocated-raw-loop-virtio-blk-v1", Filesystem: "ext4", Transport: "virtio-blk-pci", Pool: katalinux.Filesystem{Root: "/tuple/pool", Device: 1, Bytes: 8 << 30, UUID: "12345678-1234-1234-1234-123456789abc", BackingDevice: "/dev/disk/by-id/unit-pool"}, Bytes: 2 << 30, HeadroomBytes: 256 << 20, PoolReservationBytes: (2 << 30) + (256 << 20), MaxConcurrentAllocations: 2, DeviceDirectory: "/run/tuple/devices", MkfsBinary: "/tuple/formatter", AttachmentReference: "unit attachment fixture; not a live result", PhysicalReservationReference: "unit reservation fixture; not a live result"}, Runtime: katalinux.Filesystem{Root: "/tuple/runtime", Device: 2, Bytes: 1 << 30, UUID: "12345678-1234-1234-1234-123456789abc", BackingDevice: "/dev/disk/by-id/unit-runtime"}, DockerRoot: "/tuple/docker", OuterBytes: 1 << 30, LogBytes: 20 << 20, ManagementFreeBytes: 256 << 20}
	m.Budget = katalinux.Budget{Guest: protocol.ResourceBudget{CpuMillis: "1000", MemoryBytes: "2147483648", StorageBytes: "2147483648", Slots: "1"}, Overhead: protocol.ResourceBudget{CpuMillis: "250", MemoryBytes: "536870912", StorageBytes: "4294967296", Slots: "0"}, Effective: protocol.ResourceBudget{CpuMillis: "1250", MemoryBytes: "2684354560", StorageBytes: "6442450944", Slots: "1"}}
	spec := qualfixture.PrepareSpec{Version: "runnerd09-prepare-v1", Bundle: b, Manifest: m, Binding: katalinux.LabBinding{CaseID: "fixture", InstallationID: f.config.Identity.HostId, HostID: f.config.Identity.HostId, TenantID: f.config.Identity.HostId, PoolID: f.config.Identity.HostId, Repository: b.Daemon.Execution.Repository, ServiceUID: 10001, BootID: f.config.BootID, MachineUUID: "unit-machine", ControlPlaneURL: b.Daemon.ControlPlaneURL}, HostIdentity: f.config.Identity, HostPublicKey: f.config.HostPublicKey, BootstrapFile: f.config.BootstrapFile, BootstrapExpiresAt: f.config.BootstrapExpiresAt}
	return spec, f
}

func TestPrepareProducesRunnableCryptographicInputsWithoutProductionGrant(t *testing.T) {
	spec, _ := prepareInputs(t)
	m := spec.Manifest
	hash := strings.TrimPrefix(m.ImageDigest, "sha256:")
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	output := filepath.Join(dir, "plan")
	receipt, err := qualfixture.Prepare(spec, output)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Qualified || receipt.ProductionAdmission || len(receipt.RoleFiles) != 13 {
		t.Fatal("invalid provisioning claims")
	}
	for _, file := range receipt.RoleFiles {
		if strings.HasPrefix(file.Source, "operator/") {
			t.Fatal("operator key entered VM manifest")
		}
	}
	policyRaw, _ := os.ReadFile(filepath.Join(output, "client/policy.json"))
	policy, err := standardlinux.ParsePolicy(policyRaw, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots := filepath.Join(dir, "roots")
	bundles := filepath.Join(dir, "bundles")
	os.Mkdir(roots, 0700)
	os.Mkdir(bundles, 0700)
	rootRaw, _ := os.ReadFile(filepath.Join(output, "client/image-root.json"))
	os.WriteFile(filepath.Join(roots, "runnerd09-lab-image-1.json"), rootRaw, 0600)
	bundleRaw, _ := os.ReadFile(filepath.Join(output, "client/image-bundle.json"))
	os.WriteFile(filepath.Join(bundles, hash+".sigstore.json"), bundleRaw, 0600)
	verifier := standardlinux.ImageVerifier{RootDirectory: roots, BundleDirectory: bundles, ProvisionedAt: time.Now().Add(-time.Second)}
	if err = verifier.Verify(context.Background(), policy, m.ImageRepository, m.ImageDigest, time.Now()); err != nil {
		t.Fatal("real image verifier rejected generated lab signature", err)
	}
	var envelope katalinux.LabEnvelope
	data, _ := os.ReadFile(filepath.Join(output, "client/profile.json"))
	json.Unmarshal(data, &envelope)
	if envelope.Manifest.Qualified || len(envelope.Manifest.Acceptance) != 0 {
		t.Fatal("lab plan forged completed acceptance")
	}
	if _, err = qualfixture.Prepare(spec, output); err == nil {
		t.Fatal("existing campaign overwritten")
	}
}
