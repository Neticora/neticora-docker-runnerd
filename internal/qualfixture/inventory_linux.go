//go:build linux && runnerd_qualification

package qualfixture

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/provision"
	"github.com/moby/moby/client"
)

type TupleRequest struct {
	Version            string           `json:"version"`
	CaseID             string           `json:"caseId"`
	Bundle             provision.Bundle `json:"bundle"`
	ImageDigest        string           `json:"imageDigest"`
	DockerConfig       string           `json:"dockerConfig"`
	RuntimeConfig      string           `json:"runtimeConfig"`
	RuntimeSelector    string           `json:"runtimeSelector"`
	QEMUBinary         string           `json:"qemuBinary"`
	ShimBinary         string           `json:"shimBinary"`
	GuestKernel        string           `json:"guestKernel"`
	GuestKernelVersion string           `json:"guestKernelVersion"`
	GuestImage         string           `json:"guestImage"`
	PoolRoot           string           `json:"poolRoot"`
	PoolBacking        string           `json:"poolBacking"`
	RuntimeRoot        string           `json:"runtimeRoot"`
	RuntimeBacking     string           `json:"runtimeBacking"`
	DeviceDirectory    string           `json:"deviceDirectory"`
	GuestDNSServers    []string         `json:"guestDnsServers"`
}

func inspectFilesystem(root, backing string) (katalinux.Filesystem, error) {
	var stat syscall.Stat_t
	var space syscall.Statfs_t
	if hostfs.CheckAncestors(root) != nil || syscall.Stat(root, &stat) != nil || syscall.Statfs(root, &space) != nil || space.Type != 0xef53 {
		return katalinux.Filesystem{}, ErrFixture
	}
	uuid, err := exec.Command("/usr/sbin/blkid", "-s", "UUID", "-o", "value", backing).Output()
	if err != nil {
		return katalinux.Filesystem{}, err
	}
	return katalinux.Filesystem{Root: root, BackingDevice: backing, UUID: strings.TrimSpace(string(uuid)), Device: uint64(stat.Dev), Bytes: space.Blocks * uint64(space.Bsize)}, nil
}
func hashHostFile(path string) (string, error) {
	if hostfs.CheckAncestors(filepath.Dir(path)) != nil {
		return "", ErrFixture
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 4<<30 {
		return "", ErrFixture
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, io.LimitReader(file, 4<<30+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// InspectTuple observes only an explicitly selected disposable host. Observer
// config bytes are a planned, hash-pinned output; live probing rechecks them.
func InspectTuple(ctx context.Context, r TupleRequest) (PrepareSpec, error) {
	var out PrepareSpec
	if os.Geteuid() != 0 || r.Version != "runnerd09-tuple-request-v1" {
		return out, ErrFixture
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		return out, err
	}
	if _, err := provision.Parse(jsonBytes(r.Bundle)); err != nil {
		return out, err
	}
	x := r.Bundle.Daemon.Execution
	observer := r.Bundle.Observer
	name := "runnerd09-lab-" + r.CaseID
	if observer.InstallationID != name || observer.HostID != name {
		return out, ErrFixture
	}
	engine, err := dockerengine.OpenReadOnly(r.Bundle.Daemon.RuntimeEndpoint, name, nil)
	if err != nil {
		return out, err
	}
	defer engine.Close()
	endpoint, err := engine.Probe(ctx)
	if err != nil {
		return out, err
	}
	api, err := client.NewClientWithOpts(client.WithHost(r.Bundle.Daemon.RuntimeEndpoint), client.WithAPIVersionNegotiation())
	if err != nil {
		return out, err
	}
	defer api.Close()
	info, err := api.Info(ctx, client.InfoOptions{})
	if err != nil || info.Info.Driver != "overlay2" {
		return out, ErrFixture
	}
	pool, err := inspectFilesystem(r.PoolRoot, r.PoolBacking)
	if err != nil {
		return out, err
	}
	runtimeFS, err := inspectFilesystem(r.RuntimeRoot, r.RuntimeBacking)
	if err != nil {
		return out, err
	}
	osFile, err := filepath.EvalSymlinks("/etc/os-release")
	if err != nil {
		return out, err
	}
	formatter, err := filepath.EvalSymlinks("/usr/sbin/mkfs.ext4")
	if err != nil {
		return out, err
	}
	kernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return out, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return out, err
	}
	uuid, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err != nil {
		return out, err
	}
	m := katalinux.Manifest{Version: katalinux.MultiBlockVersion, Qualified: false, EndpointIdentity: endpoint, ConfigurationGeneration: "1", HostKernel: strings.TrimSpace(string(kernel)), DockerVersion: info.Info.ServerVersion, RuntimeSelector: r.RuntimeSelector, RuntimeImplementation: "runtime-rs", Hypervisor: "qemu", DockerConfig: r.DockerConfig, ObserverConfig: filepath.Join(filepath.Dir(observer.PublicKeyFile), "config.json"), RuntimeConfig: r.RuntimeConfig, HostOSFile: osFile, GuestKernel: r.GuestKernel, GuestImage: r.GuestImage, GuestKernelVersion: r.GuestKernelVersion, GuestImageVersion: filepath.Base(r.GuestImage), ImageRepository: x.ImageRepository, ImageDigest: r.ImageDigest, QEMUBinary: r.QEMUBinary, ShimBinary: r.ShimBinary, VMNamePrefix: "sandbox-", GuestStorageDriver: "overlay2", GuestDNSServers: r.GuestDNSServers, SecurityReview: "Unqualified lab candidate; independent capability/seccomp/device review remains required", Deadlines: katalinux.Deadlines{StartupSeconds: 90, HeartbeatSeconds: 30, TerminationSeconds: 30, ExecutionSeconds: 3600}, Files: map[string]string{}, HostCgroup: &katalinux.HostCgroup{Method: "systemd-transient-slice-v1", SystemctlBinary: "/usr/bin/systemctl", BusctlBinary: "/usr/bin/busctl", PidsLimit: uint64(x.PidsLimit)}}
	for path, target := range map[string]*string{r.ShimBinary: &m.KataVersion, r.QEMUBinary: &m.QEMUVersion} {
		version, err := exec.CommandContext(ctx, path, "--version").Output()
		if err != nil {
			return out, err
		}
		*target = strings.Split(strings.TrimSpace(string(version)), "\n")[0]
	}
	m.Storage = katalinux.Storage{Block: &katalinux.BlockStorage{Method: "preallocated-raw-loop-virtio-blk-v1", Filesystem: "ext4", Transport: "virtio-blk-pci", Pool: pool, Bytes: 3 << 30, HeadroomBytes: 256 << 20, DeviceDirectory: r.DeviceDirectory, MkfsBinary: formatter, AttachmentReference: "Lab virtio-blk candidate; qualification remains incomplete", PhysicalReservationReference: "Lab fully preallocated raw candidate; qualification remains incomplete", MaxConcurrentAllocations: 2, PoolReservationBytes: (3 << 30) + (256 << 20)}, Runtime: runtimeFS, DockerRoot: info.Info.DockerRootDir, OuterBytes: 1 << 30, LogBytes: 20 << 20, ManagementFreeBytes: 256 << 20}
	for _, suffix := range []string{"kata-containers", "kata-containers/shared/sandboxes", "vc/sbs", "vc/vm"} {
		m.SandboxRoots = append(m.SandboxRoots, filepath.Join(runtimeFS.Root, suffix))
	}
	m.GuestCapabilities = []string{"SYS_ADMIN", "NET_ADMIN", "MKNOD", "DAC_OVERRIDE", "CHOWN", "FOWNER", "FSETID", "SETUID", "SETGID", "SETPCAP", "SYS_CHROOT", "NET_RAW", "NET_BIND_SERVICE", "SETFCAP", "KILL", "AUDIT_WRITE", "SYS_PTRACE"}
	storage := m.Storage.Block.PoolReservationBytes + runtimeFS.Bytes + m.Storage.OuterBytes + m.Storage.LogBytes
	m.Budget = katalinux.Budget{Guest: protocol.ResourceBudget{CpuMillis: "1000", MemoryBytes: "2147483648", StorageBytes: strconv.FormatUint(m.Storage.Block.Bytes, 10), Slots: "1"}, Overhead: protocol.ResourceBudget{CpuMillis: "250", MemoryBytes: "536870912", StorageBytes: strconv.FormatUint(storage-m.Storage.Block.Bytes, 10), Slots: "0"}, Effective: protocol.ResourceBudget{CpuMillis: "1250", MemoryBytes: "2684354560", StorageBytes: strconv.FormatUint(storage, 10), Slots: "1"}}
	for _, path := range []string{m.QEMUBinary, m.ShimBinary, m.DockerConfig, m.RuntimeConfig, m.HostOSFile, m.GuestKernel, m.GuestImage, formatter, "/etc/mke2fs.conf", "/usr/bin/systemctl", "/usr/bin/busctl", "/opt/kata/libexec/virtiofsd"} {
		hash, err := hashHostFile(path)
		if err != nil {
			return out, err
		}
		m.Files[path] = hash
	}
	m.Files[m.ObserverConfig] = digest(jsonBytes(observer))
	if err = engine.CheckKataTuple(ctx, m.RuntimeSelector, m.DockerVersion, m.Storage.DockerRoot, m.ShimBinary, m.RuntimeConfig, m.DockerConfig, m.Files[m.DockerConfig]); err != nil {
		return out, err
	}
	return PrepareSpec{Version: "runnerd09-prepare-v1", Bundle: r.Bundle, Manifest: m, Binding: katalinux.LabBinding{CaseID: r.CaseID, InstallationID: name, HostID: name, TenantID: name, PoolID: name, Repository: x.Repository, ServiceUID: observer.ServiceUID, BootID: strings.TrimSpace(string(boot)), MachineUUID: strings.ToLower(strings.TrimSpace(string(uuid))), ControlPlaneURL: r.Bundle.Daemon.ControlPlaneURL}}, nil
}

// InitIdentity creates only a fresh lab identity, on the VM as its service UID.
// It never reads, overwrites or re-enrolls the existing real host identity.
func InitIdentity(caseID, endpoint, output string) (map[string]any, error) {
	expected := filepath.Join("/var/lib/neticora-runnerd09-lab/config", caseID, "client/identity.json")
	if os.Geteuid() == 0 || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`).MatchString(caseID) || output != expected || !regexp.MustCompile(`^docker-[a-f0-9]{64}$`).MatchString(endpoint) {
		return nil, ErrFixture
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	name := "runnerd09-lab-" + caseID
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	public, _ := x509.MarshalPKIXPublicKey(pub)
	private, _ := x509.MarshalPKCS8PrivateKey(key)
	defer clear(private)
	identity := protocol.HostIdentity{HostId: name, KeyId: "lab-" + digest(public)[:24], KeyVersion: "1", SessionEpoch: "1"}
	credentials := execution.Credentials{InstallationID: name, TenantID: name, EndpointIdentity: endpoint, Identity: identity, BootID: strings.TrimSpace(string(boot)), PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}
	if hostfs.CheckAncestors(filepath.Dir(output)) != nil {
		return nil, ErrFixture
	}
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	_, err = file.Write(jsonBytes(credentials))
	if err == nil {
		err = file.Sync()
	}
	file.Close()
	if err != nil {
		return nil, err
	}
	parent, err := os.Open(filepath.Dir(output))
	if err != nil {
		return nil, err
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		return nil, err
	}
	return map[string]any{"hostIdentity": identity, "hostPublicKey": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})), "bootId": credentials.BootID, "endpointIdentity": endpoint}, nil
}
