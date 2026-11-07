package katalinux

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var ErrBlockStorageRequired = errors.New("qualified per-execution block storage with overlay2 is required")

// BlockStorage binds one dedicated physical pool and one execution disk. Reserve
// the WHOLE pool in the common journal; guest discard cannot enable overcommit.
// Host loop devices are private transport, never exposed as guest loop devices.
// Kata translates the single OCI block mapping to a virtual virtio-blk disk.
type BlockStorage struct {
	Method                       string     `json:"method"`
	Filesystem                   string     `json:"filesystem"`
	Transport                    string     `json:"transport"`
	Pool                         Filesystem `json:"pool"`
	Bytes                        uint64     `json:"bytes"`
	HeadroomBytes                uint64     `json:"headroomBytes"`
	DeviceDirectory              string     `json:"deviceDirectory"`
	MkfsBinary                   string     `json:"mkfsBinary"`
	AttachmentReference          string     `json:"attachmentReference"`
	PhysicalReservationReference string     `json:"physicalReservationReference"`
}
type GuestBlockSettings struct {
	Version string `json:"version"`
	Device  string `json:"device"`
	UUID    string `json:"uuid"`
	Bytes   uint64 `json:"bytes"`
	UID     int    `json:"uid"`
}

func (p *Profile) template() string {
	if p.Manifest.Version == BlockVersion {
		return BlockTemplate
	}
	return Template
}
func (p *Profile) storageFilesystems() []Filesystem {
	if p.Manifest.Storage.Block != nil {
		return []Filesystem{p.Manifest.Storage.Block.Pool, p.Manifest.Storage.Runtime}
	}
	return []Filesystem{p.Manifest.Storage.Graph, p.Manifest.Storage.Workspace, p.Manifest.Storage.Runtime}
}
func (p *Profile) storageRoots() []string {
	out := []string{}
	for _, fs := range p.storageFilesystems() {
		out = append(out, fs.Root)
	}
	return out
}
func (p *Profile) blockNode(name string) string {
	return filepath.Join(p.Manifest.Storage.Block.DeviceDirectory, name)
}
func (p *Profile) blockUUID(name string) string {
	hash := sha256.Sum256([]byte(p.ID + "\x00" + name))
	v := hex.EncodeToString(hash[:16])
	return v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:]
}
func validVolumeIdentity(fs Filesystem) bool {
	return regexp.MustCompile(`^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`).MatchString(fs.UUID) &&
		strings.HasPrefix(fs.BackingDevice, "/dev/disk/by-id/") && filepath.Clean(fs.BackingDevice) == fs.BackingDevice &&
		filepath.Base(fs.BackingDevice) != "by-id" && !strings.ContainsAny(fs.BackingDevice, " \t\r\n\\\x00")
}
func (p *Profile) validateBlockStorage() error {
	b := p.Manifest.Storage.Block
	for _, fs := range p.storageFilesystems() {
		if (fs.UUID != "" || fs.BackingDevice != "") && !validVolumeIdentity(fs) {
			return ErrQualification
		}
	}
	if b == nil || b.Method != "preallocated-raw-loop-virtio-blk-v1" || b.Filesystem != "ext4" || b.Transport != "virtio-blk-pci" || b.Bytes > math.MaxInt64 || b.Pool.Bytes > math.MaxInt64 || b.Bytes < 1<<30 || b.Bytes%(1<<20) != 0 || b.HeadroomBytes < 256<<20 || b.Pool.Bytes < b.HeadroomBytes || b.Bytes > b.Pool.Bytes-b.HeadroomBytes || b.Pool.Device == 0 || len(b.AttachmentReference) < 20 || len(b.PhysicalReservationReference) < 20 || p.Manifest.Files[b.MkfsBinary] == "" || p.Manifest.Storage.Graph != (Filesystem{}) || p.Manifest.Storage.Workspace != (Filesystem{}) {
		return ErrQualification
	}
	for _, path := range []string{b.DeviceDirectory, b.MkfsBinary, b.Pool.Root} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, " \t\r\n\\\x00") {
			return ErrQualification
		}
	}
	for _, path := range append(p.storageRoots(), p.EvidenceDirectory, p.JournalDirectory, p.Base.BootstrapRoot, p.HealthRoot()) {
		if overlappingPaths(path, b.DeviceDirectory) {
			return ErrQualification
		}
	}
	disk, err := strconv.ParseUint(p.Manifest.Budget.Guest.StorageBytes, 10, 64)
	if err != nil || disk != b.Bytes {
		return ErrQualification
	}
	for _, cap := range []string{"SYS_ADMIN", "DAC_OVERRIDE"} {
		found := false
		for _, v := range p.Manifest.GuestCapabilities {
			if v == cap {
				found = true
			}
		}
		if !found {
			return ErrQualification
		}
	}
	return nil
}
func (p *Profile) RequireLaunchStorage() error {
	if p != nil {
		for _, fs := range p.storageFilesystems() {
			if !validVolumeIdentity(fs) {
				return ErrBlockStorageRequired
			}
		}
	}
	if p == nil || p.Manifest.Files["/etc/mke2fs.conf"] == "" || p.Manifest.Version != BlockVersion || p.Manifest.GuestStorageDriver != "overlay2" || p.validateBlockStorage() != nil {
		return ErrBlockStorageRequired
	}
	return nil
}
