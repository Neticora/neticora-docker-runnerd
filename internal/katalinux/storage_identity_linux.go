//go:build linux

package katalinux

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

// An explicit operator signature from the same offline Kata authority authorizes
// one filesystem's device-number
// transition, on this host and boot, for recovery of the observed allocation.
// It grants neither Docker-peer rebinding nor admission nor a new allocation.
type StorageReconciliation struct {
	Version         string `json:"version"`
	Purpose         string `json:"purpose"`
	Profile         string `json:"profile"`
	InstallationID  string `json:"installationId"`
	HostID          string `json:"hostId"`
	BootID          string `json:"bootId"`
	Root            string `json:"root"`
	UUID            string `json:"uuid"`
	BackingDevice   string `json:"backingDevice"`
	OldDevice       uint64 `json:"oldDevice"`
	NewDevice       uint64 `json:"newDevice"`
	AllocationName  string `json:"allocationName"`
	AllocationInode uint64 `json:"allocationInode"`
	ApprovedAt      string `json:"approvedAt"`
	ExpiresAt       string `json:"expiresAt"`
	Operator        string `json:"operator"`
	Reference       string `json:"reference"`
}
type signedStorageReconciliation struct {
	Reconciliation StorageReconciliation `json:"reconciliation"`
	Signature      string                `json:"signature"`
}

func volumeGrantName(fs Filesystem) string {
	sum := sha256.Sum256([]byte(fs.Root))
	return "storage-reconciliation-" + hex.EncodeToString(sum[:]) + ".json"
}
func verifyPersistentVolume(fs Filesystem, device uint64) error {
	if !validVolumeIdentity(fs) || hostfs.CheckAncestors(filepath.Dir(fs.BackingDevice)) != nil {
		return ErrQualification
	}
	path, err := filepath.EvalSymlinks(fs.BackingDevice)
	if err != nil || !strings.HasPrefix(path, "/dev/") || hostfs.CheckAncestors(filepath.Dir(path)) != nil {
		return ErrQualification
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ErrQualification
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFBLK || uint64(st.Rdev) != device {
		return ErrQualification
	}
	uuid, err := ext4UUID(f)
	if err != nil || uuid != fs.UUID {
		return ErrQualification
	}
	return nil
}
func (p *Profile) storageDevice(fs Filesystem) (uint64, error) {
	var st syscall.Stat_t
	if syscall.Stat(fs.Root, &st) != nil {
		return 0, ErrQualification
	}
	actual := uint64(st.Dev)
	if fs.UUID != "" || fs.BackingDevice != "" {
		if verifyPersistentVolume(fs, actual) != nil {
			return 0, ErrQualification
		}
	}
	if actual == fs.Device {
		return actual, nil
	}
	if _, err := p.storageGrant(fs, actual); err != nil {
		return 0, err
	}
	return actual, nil
}
func (p *Profile) launchStorageSession() error {
	for _, fs := range p.storageFilesystems() {
		var st syscall.Stat_t
		if !validVolumeIdentity(fs) || syscall.Stat(fs.Root, &st) != nil || uint64(st.Dev) != fs.Device || verifyPersistentVolume(fs, uint64(st.Dev)) != nil {
			return ErrQualification
		}
	}
	return nil
}
func (p *Profile) storageGrant(fs Filesystem, actual uint64) (StorageReconciliation, error) {
	raw, err := hostfs.ReadPrivate(filepath.Join(p.EvidenceDirectory, volumeGrantName(fs)), 32768)
	if err != nil {
		return StorageReconciliation{}, ErrQualification
	}
	return p.verifyStorageGrant(raw, fs, actual)
}
func (p *Profile) verifyStorageGrant(raw []byte, fs Filesystem, actual uint64) (StorageReconciliation, error) {
	var signed signedStorageReconciliation
	refuse := func() (StorageReconciliation, error) { return StorageReconciliation{}, ErrQualification }
	if _, err := protocol.CanonicalizeJSON(raw); err != nil {
		return refuse()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&signed) != nil {
		return refuse()
	}
	grant := signed.Reconciliation
	body, err := json.Marshal(grant)
	if err != nil {
		return refuse()
	}
	body, err = protocol.CanonicalizeJSON(body)
	if err != nil {
		return refuse()
	}
	keyRaw, err := hostfs.ReadPrivate(p.storageAuthority, 16384)
	if err != nil {
		return refuse()
	}
	block, rest := pem.Decode(keyRaw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return refuse()
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return refuse()
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return refuse()
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != signed.Signature || !ed25519.Verify(key, body, signature) {
		return refuse()
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return refuse()
	}
	approved, e1 := time.Parse(time.RFC3339Nano, grant.ApprovedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	now := time.Now()
	if e1 != nil || e2 != nil || approved.After(now) || !expires.After(now) || expires.Sub(approved) > time.Hour || !expires.After(approved) ||
		p.storageInstallationID == "" || p.storageHostID == "" || grant.Version != "runnerd09-storage-reconciliation-v1" || grant.Purpose != "cleanup-only" || grant.Profile != p.ID ||
		grant.BootID != strings.TrimSpace(string(boot)) || grant.InstallationID != p.storageInstallationID || grant.HostID != p.storageHostID ||
		grant.Root != fs.Root || grant.UUID != fs.UUID || grant.BackingDevice != fs.BackingDevice || !validVolumeIdentity(fs) ||
		grant.OldDevice != fs.Device || grant.NewDevice != actual || actual == fs.Device || len(grant.Operator) < 3 || len(grant.Reference) < 20 || verifyPersistentVolume(fs, actual) != nil {
		return refuse()
	}
	return grant, nil
}
func (p *Profile) recoveryBlockIdentity(r BlockRecord) (BlockRecord, error) {
	fs := p.Manifest.Storage.Block.Pool
	actual, err := p.storageDevice(fs)
	if err != nil {
		return r, err
	}
	if r.FileDevice == actual || r.FileInode == 0 {
		return r, nil
	}
	grant, err := p.storageGrant(fs, actual)
	if err != nil || r.FileDevice != fs.Device || grant.AllocationName != r.Name || grant.AllocationInode != r.FileInode {
		return r, ErrQualification
	}
	r.FileDevice = actual
	return r, nil
}

// Persist the signed artifact and an immutable digest-addressed audit copy. The
// caller must have stopped the observer service; this command never mutates a
// block mapping, execution journal, runtime, reservation or admission setting.
func persistStorageGrant(root *os.Root, name string, raw []byte) error {
	sum := sha256.Sum256(raw)
	audit := "storage-approval-" + hex.EncodeToString(sum[:]) + ".json"
	f, err := root.OpenFile(audit, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if errors.Is(err, os.ErrExist) {
		prior, e := root.ReadFile(audit)
		if e != nil || !bytes.Equal(prior, raw) {
			return ErrQualification
		}
	} else {
		if err != nil {
			return err
		}
		_, err = f.Write(raw)
		if err == nil {
			err = f.Sync()
		}
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
	}
	if err := syncRoot(root); err != nil {
		return err
	}
	tmp := name + "." + rand.Text()
	f, err = root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = root.Rename(tmp, name); err != nil {
		return err
	}
	return syncRoot(root)
}

// InstallStorageReconciliation requires a root-owned config and a separately
// signed operator artifact. Stop the observer first. Each grant is boot-bound,
// expires within one hour and is incapable of admitting or starting work.
func InstallStorageReconciliation(config, profileID, artifact string) error {
	if os.Geteuid() != 0 || !strings.HasPrefix(profileID, "docker-kata-rs-qemu-v2-") || len(profileID) != len("docker-kata-rs-qemu-v2-")+64 {
		return ErrQualification
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(profileID, "docker-kata-rs-qemu-v2-")); err != nil {
		return ErrQualification
	}
	raw, err := hostfs.ReadPrivate(config, 65536)
	if err != nil {
		return err
	}
	if _, err = protocol.CanonicalizeJSON(raw); err != nil {
		return err
	}
	var c ObserverConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || c.InstallationID == "" || c.HostID == "" || c.ServiceUID < 1 || c.NetworkID == "" {
		return ErrQualification
	}
	// Stop the service first. This lock also excludes a concurrent automatic
	// restart, even if its socket has not appeared or has already disappeared.
	lifecycle, err := lockObserverLifecycle(c.EvidenceDirectory)
	if err != nil {
		return err
	}
	defer lifecycle.Close()
	// An active or stale socket is never silently removed by a recovery tool.
	if _, err = os.Lstat(c.Socket); !errors.Is(err, os.ErrNotExist) {
		return ErrQualification
	}
	base := standardlinux.Settings{ImageRepository: "qualified-profile", NetworkID: c.NetworkID, BootstrapRoot: c.BootstrapRoot, RunnerUID: c.ServiceUID, PidsLimit: c.PidsLimit}
	p, err := Load(filepath.Join(c.ProfileDirectory, profileID+".json"), c.PublicKeyFile, c.EvidenceDirectory, c.JournalDirectory, base)
	if err != nil || p.ID != profileID || p.Manifest.ObserverConfig != config || p.Manifest.Storage.Block == nil {
		return ErrQualification
	}
	p.storageInstallationID = c.InstallationID
	p.storageHostID = c.HostID
	lock, err := p.lockBlockPool()
	if err != nil {
		return err
	}
	defer lock.Close()
	raw, err = hostfs.ReadPrivate(artifact, 32768)
	if err != nil {
		return err
	}
	var signed signedStorageReconciliation
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&signed) != nil {
		return ErrQualification
	}
	var selected *Filesystem
	for _, fs := range p.storageFilesystems() {
		if fs.Root == signed.Reconciliation.Root {
			copy := fs
			selected = &copy
		}
	}
	if selected == nil {
		return ErrQualification
	}
	var st syscall.Stat_t
	if hostfs.CheckAncestors(selected.Root) != nil || syscall.Stat(selected.Root, &st) != nil {
		return ErrQualification
	}
	grant, err := p.verifyStorageGrant(raw, *selected, uint64(st.Dev))
	if err != nil {
		return err
	}
	root, err := hostfs.OpenState(p.EvidenceDirectory)
	if err != nil {
		return err
	}
	defer root.Close()
	allocation, err := readBlockState(root, blockSlot)
	if errors.Is(err, os.ErrNotExist) || (err == nil && allocation.Phase == "released" && grant.AllocationName == "") {
		if grant.AllocationName != "" || grant.AllocationInode != 0 {
			return ErrQualification
		}
	} else if err != nil || !validBlockPhase(allocation.Phase) || allocation.Profile != p.ID || grant.AllocationName != allocation.Name || grant.AllocationInode != allocation.FileInode {
		return ErrQualification
	}
	return persistStorageGrant(root, volumeGrantName(*selected), raw)
}
