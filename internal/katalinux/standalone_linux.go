//go:build linux

package katalinux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

// ReleaseStandalone releases the journal-owned raw disk and cgroup after the
// direct engine has removed the exact container. Loop and device claims are
// reconciled by the same allocator used at launch.
func (p *Profile) ReleaseStandalone(ctx context.Context, plan dockerengine.Plan) error {
	if !p.Manifest.Standalone || p.Manifest.Storage.Block == nil || p.ObserverSocket != "" || os.Geteuid() != 0 || !ownedName(plan.Name) {
		return ErrQualification
	}
	pool, err := hostfs.OpenState(p.Manifest.Storage.Block.Pool.Root)
	if err != nil {
		return err
	}
	var owner blockPoolOwner
	ownerErr := readCheckedBlockJSON(pool, blockPoolOwnerFile, &owner)
	pool.Close()
	if ownerErr == nil && (owner.JournalDirectory != p.JournalDirectory || owner.EvidenceDirectory != p.EvidenceDirectory ||
		(p.StorageJournalID != "" && owner.JournalID != "" && owner.JournalID != p.StorageJournalID)) {
		return ErrStorageForeignOwner
	}
	if ownerErr != nil && !errors.Is(ownerErr, os.ErrNotExist) {
		return ErrStorageIndex
	}
	if _, err := p.releaseHostCgroup(ctx, plan); err != nil {
		return err
	}
	if _, err := p.blockRecord(plan); err == nil {
		if err = p.releaseBlock(ctx, plan); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// StoragePreflight checks the signed filesystems and the journal's allocation
// ownership without creating an index or owner marker.
func (p *Profile) StoragePreflight() error {
	if !p.Manifest.Standalone || p.StorageJournalID == "" || p.RequireLaunchStorage() != nil || p.launchStorageSession() != nil {
		return ErrStorageFilesystem
	}
	pool, err := hostfs.OpenState(p.Manifest.Storage.Block.Pool.Root)
	if err != nil {
		return err
	}
	defer pool.Close()
	evidence, err := hostfs.OpenState(p.EvidenceDirectory)
	if err != nil {
		return err
	}
	defer evidence.Close()
	// A foreign pool need not be opened for writing, even to create its lock.
	var owner blockPoolOwner
	if err = readCheckedBlockJSON(pool, blockPoolOwnerFile, &owner); err == nil && owner.JournalDirectory != p.JournalDirectory {
		return ErrStorageForeignOwner
	}
	lock, err := p.lockBlockPool()
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, _, err := p.checkBlockPoolOwner(pool, evidence); err != nil {
		return err
	}
	if err := p.blockInventory(""); err != nil {
		return ErrStorageIndex
	}
	return nil
}

// VerifyUnallocated is a read-only check for an already fenced attempt. A
// verified foreign owner proves this journal could not allocate from that index.
// Its own index and the exact resource paths still have to prove absence.
func (p *Profile) VerifyUnallocated(ctx context.Context, plan dockerengine.Plan) error {
	if !p.Manifest.Standalone || p.Manifest.Storage.Block == nil || !ownedName(plan.Name) {
		return ErrQualification
	}
	pool, err := hostfs.OpenState(p.Manifest.Storage.Block.Pool.Root)
	if err != nil {
		return err
	}
	defer pool.Close()
	wantFS := p.Manifest.Storage.Block.Pool
	st, err := pool.Stat(".")
	if err != nil {
		return err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || verifyPersistentVolume(wantFS, uint64(stat.Dev)) != nil {
		return ErrStorageFilesystem
	}
	lock, err := p.openBlockPoolLock(false)
	if err == nil {
		defer lock.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var owner blockPoolOwner
	ownerErr := readCheckedBlockJSON(pool, blockPoolOwnerFile, &owner)
	if ownerErr != nil && !errors.Is(ownerErr, os.ErrNotExist) {
		return ErrStorageIndex
	}
	if ownerErr == nil && (lock == nil || owner.Version != "runnerd09-block-pool-owner-v1" ||
		owner.PoolUUID != wantFS.UUID || owner.BackingDevice != wantFS.BackingDevice ||
		owner.JournalDirectory == "" || owner.EvidenceDirectory == "") {
		return ErrStorageIndex
	}
	evidence, err := hostfs.OpenState(p.EvidenceDirectory)
	if err != nil {
		return err
	}
	defer evidence.Close()
	foreign := ownerErr == nil && owner.JournalDirectory != p.JournalDirectory && owner.EvidenceDirectory != p.EvidenceDirectory
	if ownerErr == nil && !foreign && (owner.JournalDirectory != p.JournalDirectory || owner.EvidenceDirectory != p.EvidenceDirectory ||
		(p.StorageJournalID != "" && owner.JournalID != "" && owner.JournalID != p.StorageJournalID)) {
		return ErrStorageForeignOwner
	}
	_, indexErr := evidence.Lstat(blockSlotsFile)
	if foreign && errors.Is(indexErr, os.ErrNotExist) {
		if _, err = evidence.Lstat(blockSlot); !errors.Is(err, os.ErrNotExist) {
			return ErrStorageIndex
		}
	} else {
		index, err := p.readBlockSlots(evidence)
		if err != nil {
			return err
		}
		if _, exists := index.Active[plan.Name]; exists {
			return ErrQualification
		}
	}
	for _, name := range []string{plan.Name + ".block.json", plan.Name + ".json"} {
		if _, err = evidence.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return ErrQualification
		}
	}
	if _, err := p.cgroupRecord(plan); !errors.Is(err, os.ErrNotExist) {
		return ErrQualification
	}
	return p.VerifyExecutionDevicesAbsent(ctx, plan)
}

// VerifyExecutionDevicesAbsent checks the exact storage names and the native
// loop table. It never detaches a device or consults a foreign allocation index.
func (p *Profile) VerifyExecutionDevicesAbsent(ctx context.Context, plan dockerengine.Plan) error {
	if p.Manifest.Storage.Block == nil || !ownedName(plan.Name) {
		return ErrQualification
	}
	raw := p.rawPath(plan.Name)
	device := filepath.Join(p.Manifest.Storage.Block.DeviceDirectory, plan.Name)
	pool := p.Manifest.Storage.Block.Pool
	st, err := os.Stat(pool.Root)
	if err != nil {
		return ErrStorageFilesystem
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || verifyPersistentVolume(pool, uint64(stat.Dev)) != nil {
		return ErrStorageFilesystem
	}
	for _, path := range []string{raw, device} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return ErrQualification
		}
	}
	loops, err := filepath.Glob("/sys/block/loop*/loop/backing_file")
	if err != nil {
		return err
	}
	for _, loop := range loops {
		backing, err := os.ReadFile(loop)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if strings.TrimSuffix(strings.TrimSpace(string(backing)), " (deleted)") == raw {
			return ErrQualification
		}
	}
	return p.hostCgroupAbsent(ctx, plan)
}
