//go:build linux

package katalinux

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"golang.org/x/sys/unix"
)

// A root-only durable slot is written BEFORE any backing file or loop effect.
// Released per-execution tombstones prevent recreating an old attempt. The common
// journal independently retains the entire physical pool reservation until CLEANED.

const blockSlot = "block-active.json"

func (p *Profile) rawPath(name string) string {
	return filepath.Join(p.Manifest.Storage.Block.Pool.Root, name+".raw")
}
func writeBlockState(root *os.Root, name string, record BlockRecord) error {
	record.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	body, err = protocol.CanonicalizeJSON(body)
	if err != nil {
		return err
	}
	h := sha256.Sum256(body)
	raw, err := json.Marshal(struct {
		Record BlockRecord `json:"record"`
		Hash   string      `json:"hash"`
	}{record, hex.EncodeToString(h[:])})
	if err != nil {
		return err
	}
	tmp := name + "." + rand.Text()
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
func readBlockState(root *os.Root, name string) (BlockRecord, error) {
	var record BlockRecord
	raw, err := root.ReadFile(name)
	if err != nil {
		return record, err
	}
	if len(raw) > 32768 {
		return record, ErrQualification
	}
	if _, err = protocol.CanonicalizeJSON(raw); err != nil {
		return record, ErrQualification
	}
	var value struct {
		Record BlockRecord `json:"record"`
		Hash   string      `json:"hash"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&value) != nil {
		return record, ErrQualification
	}
	body, _ := json.Marshal(value.Record)
	body, err = protocol.CanonicalizeJSON(body)
	if err != nil {
		return record, err
	}
	h := sha256.Sum256(body)
	if value.Hash != hex.EncodeToString(h[:]) {
		return record, ErrQualification
	}
	return value.Record, nil
}
func syncRoot(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (p *Profile) matchBlock(r BlockRecord, plan dockerengine.Plan) bool {
	return r.Version == "runnerd09-block-allocation-v1" && r.Profile == p.ID && r.Name == plan.Name && r.UUID == p.blockUUID(plan.Name) && r.Bytes == p.Manifest.Storage.Block.Bytes && reflect.DeepEqual(r.Labels, plan.Config.Labels)
}
func blockFile(root *os.Root, name string) (*os.File, syscall.Stat_t, error) {
	var st syscall.Stat_t
	f, err := root.OpenFile(name, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, st, err
	}
	if syscall.Fstat(int(f.Fd()), &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0777 != 0600 || st.Uid != 0 || st.Nlink != 1 {
		f.Close()
		return nil, st, ErrQualification
	}
	return f, st, nil
}
func checkRawIdentity(r BlockRecord, st syscall.Stat_t) error {
	if uint64(st.Dev) != r.FileDevice || st.Ino != r.FileInode || uint64(st.Size) != r.Bytes {
		return ErrQualification
	}
	return nil
}
func ext4UUID(f *os.File) (string, error) {
	b := make([]byte, 120)
	if _, err := f.ReadAt(b, 1024); err != nil {
		return "", err
	}
	if b[56] != 0x53 || b[57] != 0xef {
		return "", ErrQualification
	}
	v := hex.EncodeToString(b[104:120])
	return v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:], nil
}
func (p *Profile) blockInventory(allowed string) error {
	entries, err := os.ReadDir(p.Manifest.Storage.Block.Pool.Root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != "lost+found" && entry.Name() != ".runnerd.lock" && entry.Name() != allowed+".raw" {
			return ErrQualification
		}
	}
	nodes, err := os.ReadDir(p.Manifest.Storage.Block.DeviceDirectory)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, node := range nodes {
		if node.Name() != allowed {
			return ErrQualification
		}
	}
	// Missing metadata must not hide an unlinked-but-still-attached backing file.
	loops, err := filepath.Glob("/sys/block/loop*/loop/backing_file")
	if err != nil {
		return err
	}
	for _, file := range loops {
		raw, err := os.ReadFile(file)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		path := strings.TrimSpace(string(raw))
		if strings.HasPrefix(path, p.Manifest.Storage.Block.Pool.Root+"/") && (allowed == "" || path != p.rawPath(allowed)) {
			return ErrQualification
		}
	}
	return nil
}

// Lock the physical pool across observer instances, including differently named
// service sockets. Never wait past a request deadline or allow parallel allocators.
func (p *Profile) lockBlockPool() (*os.File, error) {
	pool, err := hostfs.OpenState(p.Manifest.Storage.Block.Pool.Root)
	if err != nil {
		return nil, err
	}
	defer pool.Close()
	f, err := pool.OpenFile(".runnerd.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0777 != 0600 || st.Uid != 0 || st.Nlink != 1 || unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		f.Close()
		return nil, ErrQualification
	}
	return f, nil
}
func (p *Profile) prepareBlock(ctx context.Context, plan dockerengine.Plan) error {
	if os.Geteuid() != 0 || !ownedName(plan.Name) || p.RequireLaunchStorage() != nil || p.launchStorageSession() != nil {
		return ErrQualification
	}
	lock, err := p.lockBlockPool()
	if err != nil {
		return err
	}
	defer lock.Close()
	root, err := hostfs.OpenState(p.EvidenceDirectory)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err = readBlockState(root, plan.Name+".block.json"); err == nil {
		return ErrQualification
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	r, err := readBlockState(root, blockSlot)
	if err == nil && r.Phase == "released" {
		final, e := readBlockState(root, r.Name+".block.json")
		if e != nil || final.Phase != "released" || !sameAllocation(r, final) {
			return ErrQualification
		}
	}
	if errors.Is(err, os.ErrNotExist) || (err == nil && r.Phase == "released") {
		if p.blockInventory("") != nil {
			return ErrQualification
		}
		boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if err != nil {
			return err
		}
		r = BlockRecord{Version: "runnerd09-block-allocation-v1", Profile: p.ID, Name: plan.Name, Labels: plan.Config.Labels, Phase: "claiming", UUID: p.blockUUID(plan.Name), Bytes: p.Manifest.Storage.Block.Bytes, BootID: strings.TrimSpace(string(boot))}
		if err = writeBlockState(root, blockSlot, r); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if !p.matchBlock(r, plan) || r.Phase == "releasing" || r.Phase == "released" || p.blockInventory(plan.Name) != nil {
		return ErrQualification
	}
	pool, err := hostfs.OpenState(p.Manifest.Storage.Block.Pool.Root)
	if err != nil {
		return err
	}
	defer pool.Close()
	file := plan.Name + ".raw"
	if r.Phase == "claiming" {
		f, err := pool.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if errors.Is(err, os.ErrExist) {
			f, _, err = blockFile(pool, file)
		}
		if err != nil {
			return err
		}
		var st syscall.Stat_t
		if err = syscall.Fstat(int(f.Fd()), &st); err == nil && (st.Size < 0 || uint64(st.Size) > r.Bytes) {
			err = ErrQualification
		}
		if err == nil {
			err = f.Sync()
		}
		f.Close()
		if err != nil {
			return err
		}
		if err = syncRoot(pool); err != nil {
			return err
		}
		r.FileDevice = uint64(st.Dev)
		r.FileInode = st.Ino
		r.Phase = "allocating"
		if err = writeBlockState(root, blockSlot, r); err != nil {
			return err
		}
	}
	f, st, err := blockFile(pool, file)
	if err != nil {
		return err
	}
	defer f.Close()
	if uint64(st.Dev) != r.FileDevice || st.Ino != r.FileInode {
		return ErrQualification
	}
	if r.Phase == "allocating" {
		if st.Size < 0 || uint64(st.Size) > r.Bytes {
			return ErrQualification
		}
		var fs syscall.Statfs_t
		if syscall.Statfs(p.Manifest.Storage.Block.Pool.Root, &fs) != nil {
			return ErrQualification
		}
		needed := r.Bytes - uint64(st.Size)
		if uint64(fs.Bavail)*uint64(fs.Bsize) < needed+p.Manifest.Storage.Block.HeadroomBytes {
			return ErrQualification
		}
		if err = unix.Fallocate(int(f.Fd()), 0, 0, int64(r.Bytes)); err != nil {
			return err
		}
		if err = f.Sync(); err != nil {
			return err
		}
		if err = syscall.Fstat(int(f.Fd()), &st); err != nil || uint64(st.Blocks)*512 < r.Bytes {
			return ErrQualification
		}
		r.Phase = "allocated"
		if err = writeBlockState(root, blockSlot, r); err != nil {
			return err
		}
	}
	if err = checkRawIdentity(r, st); err != nil {
		return err
	}
	if r.Phase == "allocated" {
		if uuid, e := ext4UUID(f); e != nil || uuid != r.UUID {
			binary := p.Manifest.Storage.Block.MkfsBinary
			if digestFile(binary, p.Manifest.Files[binary]) != nil || digestFile("/etc/mke2fs.conf", p.Manifest.Files["/etc/mke2fs.conf"]) != nil {
				return ErrQualification
			}
			cmd := exec.CommandContext(ctx, binary, "-t", "ext4", "-q", "-F", "-m", "0", "-U", r.UUID, "-E", "nodiscard,lazy_itable_init=0,lazy_journal_init=0", "/proc/self/fd/3")
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "MKE2FS_CONFIG=/etc/mke2fs.conf"}
			cmd.ExtraFiles = []*os.File{f}
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			if err = cmd.Run(); err != nil {
				return ErrQualification
			}
		}
		if err = f.Sync(); err != nil {
			return err
		}
		if uuid, e := ext4UUID(f); e != nil || uuid != r.UUID {
			return ErrQualification
		}
		r.Phase = "formatted"
		if err = writeBlockState(root, blockSlot, r); err != nil {
			return err
		}
	}
	loops, err := loopsFor(r)
	if err != nil || len(loops) > 1 {
		return ErrQualification
	}
	if r.Phase == "formatted" {
		if len(loops) == 0 {
			dev, err := attachLoop(f, r)
			if err != nil {
				return err
			}
			loops = []uint64{dev}
		}
		r.LoopDevice = loops[0]
		if err = p.ensureBlockNode(plan.Name, r.LoopDevice); err != nil {
			return err
		}
		r.Phase = "ready"
		if err = writeBlockState(root, blockSlot, r); err != nil {
			return err
		}
	}
	return p.verifyBlock(plan)
}
func (p *Profile) verifyBlock(plan dockerengine.Plan) error {
	if p.ObserverSocket != "" {
		return p.remote(context.Background(), "verify-block", "", plan)
	}
	if p.launchStorageSession() != nil {
		return ErrQualification
	}
	r, err := p.blockRecord(plan)
	if err != nil || r.Phase != "ready" {
		return ErrQualification
	}
	pool, err := hostfs.OpenState(p.Manifest.Storage.Block.Pool.Root)
	if err != nil {
		return err
	}
	defer pool.Close()
	f, st, err := blockFile(pool, plan.Name+".raw")
	if err != nil {
		return err
	}
	defer f.Close()
	if checkRawIdentity(r, st) != nil || uint64(st.Blocks)*512 < r.Bytes {
		return ErrQualification
	}
	if uuid, e := ext4UUID(f); e != nil || uuid != r.UUID {
		return ErrQualification
	}
	loops, err := loopsFor(r)
	if err != nil || len(loops) != 1 || loops[0] != r.LoopDevice {
		return ErrQualification
	}
	return p.checkBlockNode(plan.Name, r.LoopDevice, false)
}
func (p *Profile) VerifyStorage(ctx context.Context, plan dockerengine.Plan) error {
	if p.Manifest.Storage.Block == nil {
		return ErrBlockStorageRequired
	}
	if p.ObserverSocket != "" {
		return p.remote(ctx, "verify-block", "", plan)
	}
	return p.verifyBlock(plan)
}
func (p *Profile) blockRecord(plan dockerengine.Plan) (BlockRecord, error) {
	root, err := hostfs.OpenState(p.EvidenceDirectory)
	if err != nil {
		return BlockRecord{}, err
	}
	defer root.Close()
	r, err := readBlockState(root, blockSlot)
	if err == nil && p.matchBlock(r, plan) {
		if r.Phase == "released" {
			final, e := readBlockState(root, plan.Name+".block.json")
			if e != nil || final.Phase != "released" || !sameAllocation(r, final) {
				return BlockRecord{}, ErrQualification
			}
		}
		return r, nil
	}
	final, e := readBlockState(root, plan.Name+".block.json")
	if e != nil || !p.matchBlock(final, plan) || final.Phase != "released" {
		return BlockRecord{}, ErrQualification
	}
	return final, nil
}
func (p *Profile) releaseBlock(ctx context.Context, plan dockerengine.Plan, guards ...func() error) error {
	verifyOwners := func() error {
		for _, guard := range guards {
			if err := guard(); err != nil {
				return err
			}
		}
		return nil
	}
	if err := verifyOwners(); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return ErrQualification
	}
	lock, err := p.lockBlockPool()
	if err != nil {
		return err
	}
	defer lock.Close()
	r, err := p.blockRecord(plan)
	if err != nil {
		return err
	}
	if r.Phase == "released" {
		return p.blockReleased(plan, r)
	}
	root, err := hostfs.OpenState(p.EvidenceDirectory)
	if err != nil {
		return err
	}
	defer root.Close()
	pool, err := hostfs.OpenState(p.Manifest.Storage.Block.Pool.Root)
	if err != nil {
		return err
	}
	defer pool.Close()
	f, st, openErr := blockFile(pool, plan.Name+".raw")
	if openErr == nil {
		f.Close()
	} else if !errors.Is(openErr, os.ErrNotExist) {
		return openErr
	}
	physical, err := p.recoveryBlockIdentity(r)
	if err != nil {
		return err
	}
	if openErr == nil && r.FileInode != 0 {
		if uint64(st.Dev) != physical.FileDevice || st.Ino != physical.FileInode {
			return ErrQualification
		}
		// Compare and persist the original durable identity; physical operations
		// below use only the separately authorized session device number.
		st.Dev = r.FileDevice
	}
	var info *syscall.Stat_t
	if openErr == nil {
		info = &st
	}
	r, err = releaseIntent(r, info, errors.Is(openErr, os.ErrNotExist))
	if err != nil {
		return err
	}
	if err = writeBlockState(root, blockSlot, r); err != nil {
		return err
	}
	physical, err = p.recoveryBlockIdentity(r)
	if err != nil {
		return err
	}
	loops, err := loopsFor(physical)
	if err != nil || len(loops) > 1 {
		return ErrQualification
	}
	// A crash may occur after attachment but before the ready record. Recover
	// only a loop proven by backing inode/device, never a recycled loop number.
	if len(loops) == 1 && r.LoopDevice == 0 {
		r.LoopDevice = loops[0]
		physical.LoopDevice = loops[0]
		if err = writeBlockState(root, blockSlot, r); err != nil {
			return err
		}
	}
	users := physical
	users.LoopDevice = 0
	if len(loops) == 1 {
		users.LoopDevice = loops[0]
	}
	if err = noBlockUsers(ctx, users); err != nil {
		return err
	}
	if len(loops) > 0 {
		if err = loopMounted(ctx, loops[0]); err != nil {
			return err
		}
		if err = detachLoop(loops[0], physical); err != nil {
			return err
		}
	}
	loops, err = loopsFor(physical)
	if err != nil || len(loops) != 0 {
		return ErrQualification
	}
	if err = settledBlockAbsence(ctx, physical); err != nil {
		return err
	}
	if p.layout() != nil {
		return ErrQualification
	}
	if err = verifyOwners(); err != nil {
		return err
	}
	if err = p.removeBlockNode(plan.Name, r.LoopDevice); err != nil {
		return err
	}
	if openErr == nil {
		if err = pool.Remove(plan.Name + ".raw"); err != nil {
			return err
		}
		if err = syncRoot(pool); err != nil {
			return err
		}
	}
	// Recheck after unlink as well: a successful lazy detach or unlink alone is
	// never a capacity-release fact. Open deleted files still match their inode.
	if err = settledBlockAbsence(ctx, physical); err != nil {
		return err
	}
	if p.layout() != nil {
		return ErrQualification
	}
	if err = verifyOwners(); err != nil {
		return err
	}
	r.Phase = "released"
	if err = writeBlockState(root, plan.Name+".block.json", r); err != nil {
		return err
	}
	return writeBlockState(root, blockSlot, r)
}
func (p *Profile) blockReleased(plan dockerengine.Plan, r BlockRecord) error {
	if r.Phase != "released" {
		return ErrQualification
	}
	if _, err := os.Lstat(p.rawPath(plan.Name)); !errors.Is(err, os.ErrNotExist) {
		return ErrQualification
	}
	if _, err := os.Lstat(p.blockNode(plan.Name)); !errors.Is(err, os.ErrNotExist) {
		return ErrQualification
	}
	physical, err := p.recoveryBlockIdentity(r)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return settledBlockAbsence(ctx, physical)
}

// All loop discovery uses backing inode/device, never a cached /dev/loop number.
// Loop numbers can be reused after reboot; unrelated mappings are never detached.
func loopsFor(r BlockRecord) ([]uint64, error) {
	if r.FileInode == 0 {
		return nil, nil
	}
	entries, err := filepath.Glob("/sys/block/loop*")
	if err != nil {
		return nil, err
	}
	out := []uint64{}
	for _, entry := range entries {
		if _, e := os.Stat(filepath.Join(entry, "loop", "backing_file")); errors.Is(e, os.ErrNotExist) {
			continue
		} else if e != nil {
			return nil, e
		}
		fd, err := unix.Open(filepath.Join("/dev", filepath.Base(entry)), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		info, e := unix.IoctlLoopGetStatus64(fd)
		var st unix.Stat_t
		se := unix.Fstat(fd, &st)
		unix.Close(fd)
		if errors.Is(e, unix.ENXIO) {
			continue
		}
		if e != nil || se != nil {
			return nil, ErrQualification
		}
		if info.Device == r.FileDevice && info.Inode == r.FileInode {
			if info.Offset != 0 || info.Sizelimit != r.Bytes || info.Encrypt_type != 0 || info.Flags&unix.LO_FLAGS_READ_ONLY != 0 {
				return nil, ErrQualification
			}
			out = append(out, uint64(st.Rdev))
		}
	}
	return out, nil
}
func attachLoop(f *os.File, r BlockRecord) (uint64, error) {
	control, err := unix.Open("/dev/loop-control", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(control)
	for attempt := 0; attempt < 8; attempt++ {
		n, err := unix.IoctlRetInt(control, unix.LOOP_CTL_GET_FREE)
		if err != nil {
			return 0, err
		}
		path := "/dev/loop" + strconv.Itoa(n)
		fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return 0, err
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK || unix.Major(uint64(st.Rdev)) != 7 {
			unix.Close(fd)
			return 0, ErrQualification
		}
		err = unix.IoctlLoopConfigure(fd, &unix.LoopConfig{Fd: uint32(f.Fd()), Size: 512, Info: unix.LoopInfo64{Sizelimit: r.Bytes}})
		unix.Close(fd)
		if errors.Is(err, unix.EBUSY) {
			continue
		}
		if err != nil {
			return 0, err
		}
		return uint64(st.Rdev), nil
	}
	return 0, ErrQualification
}
func detachLoop(dev uint64, r BlockRecord) error {
	fd, err := unix.Open("/dev/loop"+strconv.FormatUint(uint64(unix.Minor(dev)), 10), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	info, err := unix.IoctlLoopGetStatus64(fd)
	if err != nil || info.Device != r.FileDevice || info.Inode != r.FileInode || info.Sizelimit != r.Bytes {
		return ErrQualification
	}
	return unix.IoctlSetInt(fd, unix.LOOP_CLR_FD, 0)
}
func (p *Profile) ensureBlockNode(name string, dev uint64) error {
	dir := p.Manifest.Storage.Block.DeviceDirectory
	if hostfs.CheckAncestors(filepath.Dir(dir)) != nil {
		return ErrQualification
	}
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	root, err := hostfs.OpenState(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	if err = unix.Mknodat(int(file.Fd()), name, unix.S_IFBLK|0600, int(dev)); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err = p.checkBlockNode(name, dev, false); err != nil {
		return err
	}
	return syncRoot(root)
}
func (p *Profile) checkBlockNode(name string, dev uint64, absentOK bool) error {
	var st syscall.Stat_t
	err := syscall.Lstat(p.blockNode(name), &st)
	if errors.Is(err, os.ErrNotExist) && absentOK {
		return nil
	}
	if err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFBLK || st.Mode&0777 != 0600 || st.Uid != 0 || uint64(st.Rdev) != dev {
		return ErrQualification
	}
	return nil
}
func (p *Profile) removeBlockNode(name string, dev uint64) error {
	if err := p.checkBlockNode(name, dev, true); err != nil {
		return err
	}
	root, err := hostfs.OpenState(p.Manifest.Storage.Block.DeviceDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	if err = root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncRoot(root)
}
func sameAllocation(a, b BlockRecord) bool {
	return a.Version == b.Version && a.Profile == b.Profile && a.Name == b.Name && a.UUID == b.UUID && a.Bytes == b.Bytes && a.FileDevice == b.FileDevice && a.FileInode == b.FileInode && a.LoopDevice == b.LoopDevice && reflect.DeepEqual(a.Labels, b.Labels)
}
func verifyVMMBlock(processes []Process, r BlockRecord, qemu string) error {
	for _, process := range processes {
		if process.Executable != qemu {
			continue
		}
		dir := filepath.Join("/proc", strconv.Itoa(process.PID), "fd")
		fds, err := os.ReadDir(dir)
		if err != nil {
			return ErrQualification
		}
		for _, fd := range fds {
			var st syscall.Stat_t
			err = syscall.Stat(filepath.Join(dir, fd.Name()), &st)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return ErrQualification
			}
			if (st.Mode&syscall.S_IFMT == syscall.S_IFBLK && uint64(st.Rdev) == r.LoopDevice) || (st.Mode&syscall.S_IFMT == syscall.S_IFREG && uint64(st.Dev) == r.FileDevice && st.Ino == r.FileInode) {
				return nil
			}
		}
	}
	return ErrQualification
}

func validBlockPhase(phase string) bool {
	switch phase {
	case "claiming", "allocating", "allocated", "formatted", "ready", "releasing", "released":
		return true
	}
	return false
}

// Missing storage is only expected before first creation or after a durable
// release intent. An unexpected disappearance must never promote its own retry
// into trusted absence by writing a release intent first.
func releaseIntent(r BlockRecord, st *syscall.Stat_t, missing bool) (BlockRecord, error) {
	if !validBlockPhase(r.Phase) || r.Phase == "released" {
		return r, ErrQualification
	}
	if missing {
		if r.Phase != "claiming" && r.Phase != "releasing" {
			return r, ErrQualification
		}
		if r.Phase == "claiming" && r.FileInode != 0 {
			return r, ErrQualification
		}
	} else {
		if st == nil || st.Size < 0 || uint64(st.Size) > r.Bytes {
			return r, ErrQualification
		}
		if r.FileInode == 0 && r.Phase == "claiming" {
			r.FileDevice = uint64(st.Dev)
			r.FileInode = st.Ino
		}
		if r.FileDevice != uint64(st.Dev) || r.FileInode != st.Ino {
			return r, ErrQualification
		}
	}
	r.Phase = "releasing"
	return r, nil
}

// Two independent observations permit deferred kernel detach to finish without
// interpreting LOOP_CLR_FD success as proof. Any uncertainty keeps the intent.
func settledBlockAbsence(ctx context.Context, r BlockRecord) error {
	for i := 0; i < 2; i++ {
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		loops, err := loopsFor(r)
		if err != nil || len(loops) != 0 {
			return ErrQualification
		}
		if r.LoopDevice != 0 {
			if err := loopMounted(ctx, r.LoopDevice); err != nil {
				return err
			}
		}
		if err := noBlockUsers(ctx, r); err != nil {
			return err
		}
	}
	return nil
}
