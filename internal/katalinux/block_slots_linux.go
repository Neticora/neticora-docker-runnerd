//go:build linux

package katalinux

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

const blockSlotsFile = "block-slots.json"
const blockPoolOwnerFile = ".runnerd.owner.json"

type blockAllocation struct {
	Record        BlockRecord `json:"record"`
	ReservedBytes uint64      `json:"reservedBytes"`
}

type blockSlots struct {
	Version       string                     `json:"version"`
	PoolRoot      string                     `json:"poolRoot"`
	PoolUUID      string                     `json:"poolUUID"`
	BackingDevice string                     `json:"backingDevice"`
	JournalID     string                     `json:"journalId,omitempty"`
	Active        map[string]blockAllocation `json:"active"`
}

type blockPoolOwner struct {
	Version           string `json:"version"`
	EvidenceDirectory string `json:"evidenceDirectory"`
	EvidenceDevice    uint64 `json:"evidenceDevice"`
	EvidenceInode     uint64 `json:"evidenceInode"`
	JournalDirectory  string `json:"journalDirectory"`
	JournalID         string `json:"journalId,omitempty"`
	PoolUUID          string `json:"poolUUID"`
	BackingDevice     string `json:"backingDevice"`
}

// All index operations run under the physical pool's flock. A single durable
// index commits every outstanding slice reservation before any backing effect.
// Its directory is outside execution storage. The pool owner binds that index
// location so another observer cannot admit against an independent empty index.
func writeCheckedBlockJSON(root *os.Root, name string, record any) error {
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	body, err = protocol.CanonicalizeJSON(body)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(body)
	raw, err := json.Marshal(struct {
		Record json.RawMessage `json:"record"`
		Hash   string          `json:"hash"`
	}{body, hex.EncodeToString(hash[:])})
	if err != nil || len(raw) > 1048576 {
		return ErrQualification
	}
	tmp := name + "." + rand.Text()
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	if err = root.Rename(tmp, name); err != nil {
		return err
	}
	return syncRoot(root)
}

func readCheckedBlockJSON(root *os.Root, name string, record any) error {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return ErrQualification
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1048577))
	if err != nil || len(raw) > 1048576 {
		return ErrQualification
	}
	if _, err = protocol.CanonicalizeJSON(raw); err != nil {
		return ErrQualification
	}
	var envelope struct {
		Record json.RawMessage `json:"record"`
		Hash   string          `json:"hash"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil {
		return ErrQualification
	}
	body, err := protocol.CanonicalizeJSON(envelope.Record)
	if err != nil {
		return ErrQualification
	}
	hash := sha256.Sum256(body)
	if envelope.Hash != hex.EncodeToString(hash[:]) {
		return ErrQualification
	}
	d = json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(record) != nil {
		return ErrQualification
	}
	return nil
}

func (p *Profile) readBlockSlots(root *os.Root) (blockSlots, error) {
	b := p.Manifest.Storage.Block
	index := blockSlots{Version: "runnerd09-block-slots-v1", PoolRoot: b.Pool.Root, PoolUUID: b.Pool.UUID, BackingDevice: b.Pool.BackingDevice, Active: map[string]blockAllocation{}}
	err := readCheckedBlockJSON(root, blockSlotsFile, &index)
	if errors.Is(err, os.ErrNotExist) {
		// The owner is committed only after the index exists. Its presence
		// therefore makes a missing index lost durability evidence, not empty
		// capacity. Never recreate it from an apparently empty directory.
		if _, ownerErr := os.Lstat(filepath.Join(b.Pool.Root, blockPoolOwnerFile)); !errors.Is(ownerErr, os.ErrNotExist) {
			return index, ErrStorageIndex
		}
		// Import the old single claim conservatively. A historical active claim
		// consumes the whole pool until its own verified cleanup completes.
		old, e := readBlockState(root, blockSlot)
		if errors.Is(e, os.ErrNotExist) {
			return index, nil
		}
		if e != nil || !ownedName(old.Name) || !validBlockPhase(old.Phase) {
			return index, ErrQualification
		}
		if old.Phase == "released" {
			final, e := readBlockState(root, old.Name+".block.json")
			if e != nil || final.Phase != "released" || !sameAllocation(old, final) {
				return index, ErrQualification
			}
			return index, nil
		}
		index.Active[old.Name] = blockAllocation{old, b.Pool.Bytes}
		return index, nil
	}
	if err != nil || index.Version != "runnerd09-block-slots-v1" || index.PoolRoot != b.Pool.Root || index.PoolUUID != b.Pool.UUID || index.BackingDevice != b.Pool.BackingDevice || index.Active == nil || len(index.Active) > 16 {
		return index, ErrQualification
	}
	var reserved uint64
	for name, allocation := range index.Active {
		r := allocation.Record
		if !ownedName(name) || r.Name != name || r.Version != "runnerd09-block-allocation-v1" || !validBlockPhase(r.Phase) || r.Phase == "released" || r.Bytes < 1<<30 || r.Bytes > b.Pool.Bytes || allocation.ReservedBytes < r.Bytes || allocation.ReservedBytes > b.Pool.Bytes-reserved {
			return index, ErrQualification
		}
		reserved += allocation.ReservedBytes
	}
	return index, nil
}

func (p *Profile) readActiveBlock(root *os.Root, name string) (BlockRecord, error) {
	index, err := p.readBlockSlots(root)
	if err != nil {
		return BlockRecord{}, err
	}
	allocation, ok := index.Active[name]
	if !ok {
		return BlockRecord{}, os.ErrNotExist
	}
	return allocation.Record, nil
}

func (p *Profile) writeActiveBlock(root *os.Root, record BlockRecord) error {
	if !ownedName(record.Name) || !validBlockPhase(record.Phase) {
		return ErrQualification
	}
	index, err := p.readBlockSlots(root)
	if err != nil {
		return err
	}
	allocation, exists := index.Active[record.Name]
	if record.Phase == "released" {
		final, e := readBlockState(root, record.Name+".block.json")
		if e != nil || final.Phase != "released" || !sameAllocation(record, final) || (exists && !sameAllocation(allocation.Record, record)) {
			return ErrQualification
		}
		delete(index.Active, record.Name)
	} else {
		if !exists {
			if record.Phase != "claiming" || len(index.Active) >= int(p.MaxConcurrentAllocations()) {
				return ErrQualification
			}
			reserved := uint64(0)
			for _, other := range index.Active {
				reserved += other.ReservedBytes
			}
			charge := p.poolReservationBytes()
			if charge > p.Manifest.Storage.Block.Pool.Bytes-reserved {
				return ErrQualification
			}
			allocation.ReservedBytes = charge
		} else if allocation.Record.Version != record.Version || allocation.Record.Profile != record.Profile || allocation.Record.UUID != record.UUID || allocation.Record.Bytes != record.Bytes || allocation.Record.BootID != record.BootID || !reflect.DeepEqual(allocation.Record.Labels, record.Labels) {
			return ErrQualification
		}
		record.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		allocation.Record = record
		index.Active[record.Name] = allocation
	}
	return writeCheckedBlockJSON(root, blockSlotsFile, index)
}

func (p *Profile) expectedPoolOwner(evidence *os.Root) (blockPoolOwner, error) {
	info, err := evidence.Stat(".")
	if err != nil {
		return blockPoolOwner{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return blockPoolOwner{}, ErrQualification
	}
	b := p.Manifest.Storage.Block
	return blockPoolOwner{
		Version: "runnerd09-block-pool-owner-v1", EvidenceDirectory: p.EvidenceDirectory,
		EvidenceDevice: uint64(st.Dev), EvidenceInode: st.Ino, JournalDirectory: p.JournalDirectory,
		JournalID: p.StorageJournalID, PoolUUID: b.Pool.UUID, BackingDevice: b.Pool.BackingDevice,
	}, nil
}

func (p *Profile) checkBlockPoolOwner(pool, evidence *os.Root) (bool, blockSlots, error) {
	want, err := p.expectedPoolOwner(evidence)
	if err != nil {
		return false, blockSlots{}, err
	}
	var current blockPoolOwner
	err = readCheckedBlockJSON(pool, blockPoolOwnerFile, &current)
	missing := errors.Is(err, os.ErrNotExist)
	if !missing {
		if err != nil {
			return false, blockSlots{}, ErrStorageIndex
		}
		if want.JournalID != "" && current.JournalID == "" {
			legacy := want
			legacy.JournalID = ""
			if current == legacy {
				return false, blockSlots{}, ErrStorageJournalBinding
			}
		}
		if current != want {
			return false, blockSlots{}, ErrStorageForeignOwner
		}
	}
	index, err := p.readBlockSlots(evidence)
	if err != nil || (missing && len(index.Active) != 0) {
		return false, blockSlots{}, ErrStorageIndex
	}
	if want.JournalID != "" && index.JournalID != want.JournalID {
		_, indexErr := evidence.Lstat(blockSlotsFile)
		_, legacyErr := evidence.Lstat(blockSlot)
		if !missing || !errors.Is(indexErr, os.ErrNotExist) || !errors.Is(legacyErr, os.ErrNotExist) {
			return false, blockSlots{}, ErrStorageIndex
		}
		index.JournalID = want.JournalID
	}
	return missing, index, nil
}

func (p *Profile) ensureBlockPoolOwner(pool, evidence *os.Root) error {
	missing, index, err := p.checkBlockPoolOwner(pool, evidence)
	if err != nil || !missing {
		return err
	}
	want, err := p.expectedPoolOwner(evidence)
	if err != nil {
		return err
	}
	// An index already committed by this journal can survive a crash before
	// the owner write. An existing index must never be replaced to add an owner.
	if _, err = evidence.Lstat(blockSlotsFile); errors.Is(err, os.ErrNotExist) {
		if err = writeCheckedBlockJSON(evidence, blockSlotsFile, index); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return writeCheckedBlockJSON(pool, blockPoolOwnerFile, want)
}
