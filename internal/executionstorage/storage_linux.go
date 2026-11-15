//go:build linux

// Package executionstorage owns disk-backed execution directories, never images,
// shared caches, journal files or enrollment credentials. Caller must establish
// original Docker disposal and mount retirement before invoking Dispose.
package executionstorage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/journal"
	"golang.org/x/sys/unix"
)

var ErrQuarantined = errors.New("execution storage ownership or retirement uncertain; quarantine retained")
var ErrCriticalPressure = errors.New("execution storage critically low; operator intervention required")
var ErrPressure = errors.New("execution storage headroom unavailable; new admission stopped")
var children = [...]string{"workspace", "home", "tmp", "diagnostics"}

func Name(id agent.Identity) string {
	raw, _ := json.Marshal(id)
	h := sha256.Sum256(raw)
	return "nrd-" + hex.EncodeToString(h[:])
}

type Manager struct {
	Path  string
	Store *journal.SQLiteStore
	Scope agent.StoreScope
}

func openDir(parent int, name string) (int, error) {
	return unix.Openat2(parent, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_DIRECTORY, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
}
func fingerprint(fd int) (journal.StorageIdentity, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_INO|unix.STATX_MNT_ID|unix.STATX_TYPE|unix.STATX_UID, &st); err != nil {
		return journal.StorageIdentity{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != os.Geteuid() {
		return journal.StorageIdentity{}, ErrQuarantined
	}
	return journal.StorageIdentity{Device: uint64(st.Dev_major)<<32 | uint64(st.Dev_minor), Inode: st.Ino}, nil
}
func (m Manager) root() (int, journal.StorageIdentity, error) {
	if !filepath.IsAbs(m.Path) || filepath.Clean(m.Path) != m.Path {
		return -1, journal.StorageIdentity{}, ErrQuarantined
	}
	r, err := hostfs.OpenState(m.Path)
	if err != nil {
		return -1, journal.StorageIdentity{}, fmt.Errorf("%w: %v", ErrQuarantined, err)
	}
	r.Close()
	fd, err := unix.Open(m.Path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, journal.StorageIdentity{}, err
	}
	fail := func() (int, journal.StorageIdentity, error) {
		unix.Close(fd)
		return -1, journal.StorageIdentity{}, ErrQuarantined
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil {
		return fail()
	}
	switch uint64(fs.Type) {
	case 0xef53, 0x58465342, 0x9123683e, 0xf2f52010:
	default:
		return fail()
	}
	id, err := fingerprint(fd)
	if err != nil {
		unix.Close(fd)
		return -1, id, err
	}
	return fd, id, nil
}
func (m Manager) Headroom(minimum uint64) error {
	fd, _, err := m.root()
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || minimum == 0 || fs.Bsize <= 0 || fs.Bavail > ^uint64(0)/uint64(fs.Bsize) {
		return ErrPressure
	}
	available := fs.Bavail * uint64(fs.Bsize)
	if available < 64<<20 || fs.Ffree < 128 || fs.Flags&unix.ST_RDONLY != 0 {
		return ErrCriticalPressure
	}
	if available < minimum || fs.Ffree < 1024 {
		return ErrPressure
	}
	return nil
}

func (m Manager) Prepare(ctx context.Context, id agent.Identity) (journal.ExecutionStorage, error) {
	fd, root, err := m.root()
	if err != nil {
		return journal.ExecutionStorage{}, err
	}
	defer unix.Close(fd)
	r, err := m.Store.StorageIntent(ctx, m.Scope, journal.ExecutionStorage{Identity: id, Endpoint: m.Scope.EndpointIdentity, Root: m.Path, Name: Name(id), RootIdentity: root, State: "intent"})
	if err != nil {
		return r, err
	}
	if r.State != "intent" && r.State != "allocated" {
		return r, ErrQuarantined
	}
	if r.State == "intent" {
		// An existing directory without a committed inode is ambiguous, including a
		// crash in this small gap. Never adopt it merely because its name matches.
		if unix.Mkdirat(fd, r.Name, 0700) != nil {
			return r, ErrQuarantined
		}
		child, e := openDir(fd, r.Name)
		if e != nil {
			return r, e
		}
		inode, e := fingerprint(child)
		if e == nil {
			e = unix.Fsync(child)
		}
		unix.Close(child)
		if e != nil {
			return r, e
		}
		if e = unix.Fsync(fd); e != nil {
			return r, e
		}
		next := r
		next.DirectoryIdentity = inode
		next.State = "allocated"
		if e = m.Store.StorageTransition(ctx, m.Scope, r, next); e != nil {
			return r, e
		}
		r = next
	}
	leaf, err := openDir(fd, r.Name)
	if err != nil {
		return r, ErrQuarantined
	}
	defer unix.Close(leaf)
	actual, err := fingerprint(leaf)
	if err != nil || actual != r.DirectoryIdentity {
		return r, ErrQuarantined
	}
	for _, name := range children {
		if err = unix.Mkdirat(leaf, name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
			return r, err
		}
		child, e := openDir(leaf, name)
		if e != nil {
			return r, ErrQuarantined
		}
		_, e = fingerprint(child)
		if e == nil {
			e = unix.Fsync(child)
		}
		unix.Close(child)
		if e != nil {
			return r, ErrQuarantined
		}
	}
	return r, unix.Fsync(leaf)
}

// Verify compares physical storage with all journal records, including disposed
// tombstones. A scan bound stops new work instead of omitting old obligations.
func (m Manager) Verify(ctx context.Context) error {
	fd, root, err := m.root()
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	rows, err := m.Store.StoragePendingRecords(ctx)
	if err != nil {
		return err
	}
	known := map[string]journal.ExecutionStorage{}
	for _, r := range rows {
		if r.Root != m.Path || r.RootIdentity != root || r.Endpoint != m.Scope.EndpointIdentity || r.Identity.InstallationID != m.Scope.InstallationID || r.Identity.TenantID != m.Scope.TenantID || r.Identity.HostID != m.Scope.HostID || r.Name != Name(r.Identity) {
			return ErrQuarantined
		}
		known[r.Name] = r
	}
	scan, err := openDir(fd, ".")
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(scan), m.Path)
	defer f.Close()
	for count := 0; ; {
		names, e := f.Readdirnames(100)
		for _, name := range names {
			count++
			if count > 10000 {
				return ErrQuarantined
			}
			r, ok := known[name]
			if !ok || r.State == "disposed" || r.State == "intent" {
				return ErrQuarantined
			}
			child, e := openDir(fd, name)
			if e != nil {
				return ErrQuarantined
			}
			actual, e := fingerprint(child)
			unix.Close(child)
			if e != nil || actual != r.DirectoryIdentity {
				return ErrQuarantined
			}
			delete(known, name)
		}
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return e
		}
	}
	for _, r := range known {
		if r.State == "allocated" {
			return ErrQuarantined
		}
	}
	return nil
}

func (m Manager) Record(ctx context.Context, id agent.Identity) (journal.ExecutionStorage, error) {
	return m.Store.StorageRecord(ctx, id)
}

// Dispose requires separately verified Docker/mount retirement. No callback can
// replace ownership checks or bless a different inode. Retiring is durable before
// the first unlink, so a crash resumes the original operation, including ENOENT.
func (m Manager) Dispose(ctx context.Context, id agent.Identity) error {
	r, err := m.Record(ctx, id)
	if err != nil {
		return err
	}
	fd, root, err := m.root()
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if r.Root != m.Path || r.RootIdentity != root || r.Name != Name(id) || r.Endpoint != m.Scope.EndpointIdentity {
		return ErrQuarantined
	}
	if r.State == "intent" {
		var st unix.Stat_t
		if err := unix.Fstatat(fd, r.Name, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			return ErrQuarantined
		}
	}
	if r.State == "allocated" || r.State == "intent" {
		next := r
		next.State = "retiring"
		if err = m.Store.StorageTransition(ctx, m.Scope, r, next); err != nil {
			return err
		}
		r = next
	}
	if r.State != "retiring" && r.State != "disposed" {
		return ErrQuarantined
	}
	leaf, err := openDir(fd, r.Name)
	if errors.Is(err, unix.ENOENT) {
		if r.State == "disposed" {
			return nil
		}
		return m.finish(ctx, r, fd)
	}
	if err != nil || r.State == "disposed" {
		if leaf >= 0 {
			unix.Close(leaf)
		}
		return ErrQuarantined
	}
	defer unix.Close(leaf)
	actual, err := fingerprint(leaf)
	if err != nil || actual != r.DirectoryIdentity {
		return ErrQuarantined
	}
	entries, e := namesAt(leaf)
	if e != nil {
		return e
	}
	for _, name := range entries {
		if !slices.Contains(children[:], name) {
			return ErrQuarantined
		}
	}
	budget := 1000000
	for _, name := range entries {
		if err = remove(ctx, leaf, name, 0, &budget); err != nil {
			return fmt.Errorf("%w: %v", ErrQuarantined, err)
		}
	}
	if err = unix.Fsync(leaf); err != nil {
		return err
	}
	// The outer directory is never job-mounted. Verify the name still identifies
	// the pinned inode before removing it; no recursive path-based removal.
	check, err := openDir(fd, r.Name)
	if err != nil {
		return ErrQuarantined
	}
	actual, err = fingerprint(check)
	unix.Close(check)
	if err != nil || actual != r.DirectoryIdentity {
		return ErrQuarantined
	}
	if err = unix.Unlinkat(fd, r.Name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return m.finish(ctx, r, fd)
}
func (m Manager) finish(ctx context.Context, r journal.ExecutionStorage, fd int) error {
	var st unix.Stat_t
	if err := unix.Fstatat(fd, r.Name, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return ErrQuarantined
	}
	current, root, err := m.root()
	if err != nil {
		return err
	}
	unix.Close(current)
	if root != r.RootIdentity {
		return ErrQuarantined
	}
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	next := r
	next.State = "disposed"
	return m.Store.StorageTransition(ctx, m.Scope, r, next)
}
func namesAt(fd int) ([]string, error) {
	copy, err := openDir(fd, ".")
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(copy), "execution-directory")
	defer f.Close()
	names, err := f.Readdirnames(10001)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	if len(names) > 10000 {
		return nil, ErrQuarantined
	}
	return names, err
}
func remove(ctx context.Context, parent int, name string, depth int, budget *int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	*budget--
	if depth > 128 || *budget < 0 || name == "." || name == ".." || filepath.Base(name) != name {
		return ErrQuarantined
	}
	// O_PATH avoids opening devices/FIFOs and pins the actual object, not a target
	// of a symlink. NO_XDEV also rejects same-filesystem bind mounts.
	probe, err := unix.Openat2(parent, name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return err
	}
	defer unix.Close(probe)
	var st unix.Stat_t
	if err = unix.Fstat(probe, &st); err != nil {
		return err
	}
	if int(st.Uid) != os.Geteuid() {
		return ErrQuarantined
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		var now unix.Stat_t
		if unix.Fstatat(parent, name, &now, unix.AT_SYMLINK_NOFOLLOW) != nil || now.Ino != st.Ino || now.Dev != st.Dev {
			return ErrQuarantined
		}
		return unix.Unlinkat(parent, name, 0)
	}
	fd, err := openDir(parent, name)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var actual unix.Stat_t
	if unix.Fstat(fd, &actual) != nil || actual.Ino != st.Ino || actual.Dev != st.Dev {
		return ErrQuarantined
	}
	names, err := namesAt(fd)
	if err != nil {
		return err
	}
	for _, child := range names {
		if err = remove(ctx, fd, child, depth+1, budget); err != nil {
			return err
		}
	}
	if err = unix.Fsync(fd); err != nil {
		return err
	}
	var now unix.Stat_t
	if unix.Fstatat(parent, name, &now, unix.AT_SYMLINK_NOFOLLOW) != nil || now.Ino != st.Ino || now.Dev != st.Dev {
		return ErrQuarantined
	}
	return unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
}
