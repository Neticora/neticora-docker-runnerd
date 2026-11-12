//go:build linux

package katalinux

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

// BrokerOrigin is protected broker state captured only from an independently
// loaded profile before execution effects. It is never accepted from IPC.
type BrokerOrigin struct {
	Version           string   `json:"version"`
	Profile           string   `json:"profile"`
	Manifest          Manifest `json:"manifest"`
	EvidenceDirectory string   `json:"evidenceDirectory"`
	JournalDirectory  string   `json:"journalDirectory"`
	EvidenceDevice    uint64   `json:"evidenceDevice"`
	EvidenceInode     uint64   `json:"evidenceInode"`
	JournalDevice     uint64   `json:"journalDevice"`
	JournalInode      uint64   `json:"journalInode"`
	JournalUID        uint32   `json:"journalUid"`
	AuthorityPEM      string   `json:"authorityPEM"`
}

func (p *Profile) BrokerOrigin() (json.RawMessage, error) {
	if !p.brokerOwned || p.cleanupOnly || p.Manifest.Storage.Block == nil {
		return nil, ErrQualification
	}
	var evidence, journal syscall.Stat_t
	if syscall.Stat(p.EvidenceDirectory, &evidence) != nil || syscall.Stat(p.JournalDirectory, &journal) != nil {
		return nil, ErrQualification
	}
	key, err := hostfs.ReadPrivate(p.storageAuthority, 16384)
	if err != nil {
		return nil, err
	}
	return json.Marshal(BrokerOrigin{Version: "runnerd-kata-origin-v1", Profile: p.ID, Manifest: p.Manifest, EvidenceDirectory: p.EvidenceDirectory, JournalDirectory: p.JournalDirectory, EvidenceDevice: uint64(evidence.Dev), EvidenceInode: evidence.Ino, JournalDevice: uint64(journal.Dev), JournalInode: journal.Ino, JournalUID: journal.Uid, AuthorityPEM: string(key)})
}
func RestoreBrokerCleanup(raw json.RawMessage, base standardlinux.Settings, installation, host string) (*Profile, error) {
	var o BrokerOrigin
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if _, err := protocol.CanonicalizeJSON(raw); err != nil {
		return nil, ErrQualification
	}
	if decoder.Decode(&o) != nil || o.Version != "runnerd-kata-origin-v1" || o.Manifest.Version != MultiBlockVersion || o.Manifest.Storage.Block == nil {
		return nil, ErrQualification
	}
	id, err := ProfileID(o.Manifest)
	if err != nil || id != o.Profile {
		return nil, ErrQualification
	}
	var evidence, journal syscall.Stat_t
	if hostfs.CheckAncestors(o.EvidenceDirectory) != nil || hostfs.CheckAncestors(filepath.Dir(o.JournalDirectory)) != nil || syscall.Stat(o.EvidenceDirectory, &evidence) != nil || syscall.Lstat(o.JournalDirectory, &journal) != nil || uint64(evidence.Dev) != o.EvidenceDevice || evidence.Ino != o.EvidenceInode || uint64(journal.Dev) != o.JournalDevice || journal.Ino != o.JournalInode || journal.Mode&syscall.S_IFMT != syscall.S_IFDIR || journal.Uid != o.JournalUID || journal.Mode&0022 != 0 {
		return nil, ErrQualification
	}
	p := &Profile{ID: id, Manifest: o.Manifest, Base: base, EvidenceDirectory: o.EvidenceDirectory, JournalDirectory: o.JournalDirectory, cleanupOnly: true, brokerOwned: true, storageAuthorityPEM: []byte(o.AuthorityPEM), storageInstallationID: installation, storageHostID: host}
	if p.validateBlockStorage() != nil || validateHostCgroup(o.Manifest) != nil || p.ProtectPaths(o.EvidenceDirectory, o.JournalDirectory, base.BootstrapRoot, p.HealthRoot()) != nil {
		return nil, ErrQualification
	}
	return p, nil
}
func ClaimBrokerRecoveryDirectory(evidence string) (func(), error) {
	if os.Geteuid() != 0 {
		return nil, ErrQualification
	}
	lock, err := lockObserverLifecycle(evidence)
	if err != nil {
		return nil, err
	}
	return func() { lock.Close() }, nil
}

// ObserveBrokerRecovery verifies original volume and pool/index ownership. A
// changed numeric device or missing immutable witness remains quarantined.
func (p *Profile) ObserveBrokerRecovery(ctx context.Context, id string, plan dockerengine.Plan) error {
	if !p.cleanupOnly || p.layout() != nil || p.priorRecoveryPoolOwner() != nil {
		return ErrQualification
	}
	block, err := p.blockRecord(plan)
	if err != nil || !p.matchBlock(block, plan) {
		return ErrQualification
	}
	if block.Phase != "released" {
		f, st, e := blockFileFromPath(p, plan.Name)
		if e != nil {
			if !os.IsNotExist(e) || block.Phase != "releasing" {
				return e
			}
			physical, e := p.recoveryBlockIdentity(block)
			if e != nil || settledBlockAbsence(ctx, physical) != nil {
				return ErrQualification
			}
		} else {
			f.Close()
			physical, e := p.recoveryBlockIdentity(block)
			if e != nil || checkRawIdentity(physical, st) != nil {
				return ErrQualification
			}
		}
	}
	raw, err := hostfs.ReadPrivate(filepath.Join(p.EvidenceDirectory, plan.Name+".json"), 32768)
	var record Evidence
	if err != nil || readEvidence(raw, &record) != nil || record.Profile != p.ID || record.Container != id || record.SpecHash != plan.Config.Labels[dockerengine.LabelPrefix+"spec"] || record.Generation != plan.Config.Labels[dockerengine.LabelPrefix+"generation"] || record.Block == nil || record.Block.BootID != block.BootID || !sameAllocation(*record.Block, block) {
		return ErrQualification
	}
	group, err := p.cgroupRecord(plan)
	if err != nil || record.Cgroup == nil || record.Cgroup.BootID != block.BootID || !sameHostCgroup(record.Cgroup, &group) {
		return ErrQualification
	}
	return ctx.Err()
}
func blockFileFromPath(p *Profile, name string) (*os.File, syscall.Stat_t, error) {
	root, err := hostfs.OpenState(p.Manifest.Storage.Block.Pool.Root)
	if err != nil {
		return nil, syscall.Stat_t{}, err
	}
	defer root.Close()
	return blockFile(root, name+".raw")
}
func (p *Profile) priorRecoveryPoolOwner() error {
	root, err := hostfs.OpenState(p.Manifest.Storage.Block.Pool.Root)
	if err != nil {
		return err
	}
	defer root.Close()
	evidence, err := hostfs.OpenState(p.EvidenceDirectory)
	if err != nil {
		return err
	}
	defer evidence.Close()
	// An absent owner cannot be initialized during recovery. The ordinary
	// helper is read-only when an exact owner already exists.
	if _, err = root.Lstat(blockPoolOwnerFile); err != nil {
		return ErrQualification
	}
	return p.ensureBlockPoolOwner(root, evidence)
}

// Recovery verifies before cleanup; it cannot prepare storage, create a slice,
// start a VM or replace original physical witnesses.
func (p *Profile) BrokerRecoverDispose(ctx context.Context, id string, plan dockerengine.Plan, guard func() error) error {
	if err := p.ObserveBrokerRecovery(ctx, id, plan); err != nil {
		return err
	}
	if err := p.VerifyAbsent(ctx, id, plan, guard); err != nil {
		return err
	}
	p.CleanHealth(plan)
	if _, err := os.Lstat(filepath.Join(p.HealthRoot(), plan.Name)); !errors.Is(err, os.ErrNotExist) {
		return ErrQualification
	}
	return nil
}

// A reboot may remove the complete private device directory. Validate every
// surviving ancestor and its tmpfs before accepting absence; never recreate it.
// This is only a node-absence check: original pool/index, raw inode, process,
// mount, loop and cgroup disposal remain independently mandatory.
func verifyBootTmpfsAbsence(path, originalBoot string) error {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || originalBoot == "" || strings.TrimSpace(string(boot)) == originalBoot || !strings.HasPrefix(path, "/run/") || filepath.Clean(path) != path {
		return ErrQualification
	}
	current := path
	for {
		info, err := os.Lstat(current)
		if err == nil {
			st, ok := info.Sys().(*syscall.Stat_t)
			var fs syscall.Statfs_t
			if !ok || st.Uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || hostfs.CheckAncestors(current) != nil || syscall.Statfs(current, &fs) != nil || uint64(fs.Type) != 0x01021994 {
				return ErrQualification
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) || current == "/run" {
			return ErrQualification
		}
		current = filepath.Dir(current)
	}
}
