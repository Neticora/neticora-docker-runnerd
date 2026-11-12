//go:build linux

package broker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

type handoffManager struct {
	ledger                         *Ledger
	root                           *os.Root
	source                         *os.Root
	uid                            int
	organization, repository, pool string
	boot                           string
}
type handoffRecord struct {
	Version string `json:"version"`
	Name    string `json:"name"`
	Boot    string `json:"boot"`
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	Hash    string `json:"hash"`
	Phase   string `json:"phase"`
}

func openHandoffs(l *Ledger, source, target string, uid int, boot, org, repo, pool string) (*handoffManager, error) {
	if uid < 1 || source == target || hostfs.CheckAncestors(filepath.Dir(source)) != nil {
		return nil, ErrRejected
	}
	info, err := os.Lstat(source)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || int(st.Uid) != uid || info.Mode().Perm() != 0700 {
		return nil, ErrRejected
	}
	s, err := os.OpenRoot(source)
	if err != nil {
		return nil, err
	}
	r, err := hostfs.OpenState(target)
	if err != nil {
		s.Close()
		return nil, err
	}
	var fs syscall.Statfs_t
	if syscall.Statfs(target, &fs) != nil || uint64(fs.Type) != 0x01021994 {
		s.Close()
		r.Close()
		return nil, ErrRejected
	}
	return &handoffManager{ledger: l, root: r, source: s, uid: uid, boot: boot, organization: org, repository: repo, pool: pool}, nil
}

func readUserFile(root *os.Root, name string, uid int, limit int64) ([]byte, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != uid || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > limit {
		return nil, ErrRejected
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrRejected
	}
	return raw, nil
}
func userDirectory(root *os.Root, name string, uid int) (*os.Root, syscall.Stat_t, error) {
	var empty syscall.Stat_t
	info, err := root.Lstat(name)
	if err != nil || !info.IsDir() {
		return nil, empty, ErrRejected
	}
	r, err := root.OpenRoot(name)
	if err != nil {
		return nil, empty, err
	}
	f, err := r.Open(".")
	if err != nil {
		r.Close()
		return nil, empty, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		r.Close()
		return nil, empty, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != uid || info.Mode().Perm() != 0700 {
		r.Close()
		return nil, empty, ErrRejected
	}
	return r, *st, nil
}
func handoffID(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}
func syncDirectory(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Prepare snapshots only controller-owned regular bytes. It cannot read a root
// secret through a controller-supplied symlink, device, hardlink or arbitrary path.
func (m *handoffManager) Prepare(p dockerengine.Plan) error {
	root, err := m.ledger.records("handoffs")
	if err != nil {
		return err
	}
	defer root.Close()
	id := handoffID(p.Name)
	var record handoffRecord
	err = readRecord(root, id, &record)
	if err == nil {
		return m.verify(p, record)
	}
	if !os.IsNotExist(err) {
		return err
	}
	if _, err = m.root.Lstat(p.Name); !os.IsNotExist(err) {
		return ErrQuarantined
	}
	src, _, err := userDirectory(m.source, p.Name, m.uid)
	if err != nil {
		return err
	}
	defer src.Close()
	raw, err := readUserFile(src, "bootstrap.json", m.uid, 131072)
	if err != nil {
		return err
	}
	defer clear(raw)
	var body struct {
		JIT          string `json:"jit"`
		Expires      string `json:"expiresAt"`
		Organization string `json:"organization"`
		Repository   string `json:"repository"`
		Pool         string `json:"pool"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if _, err = protocol.CanonicalizeJSON(raw); err != nil {
		return err
	}
	if decoder.Decode(&body) != nil || decoder.Decode(new(any)) != io.EOF || body.JIT == "" || body.Organization != m.organization || body.Repository != m.repository || body.Pool != m.pool {
		return ErrRejected
	}
	expires, err := time.Parse(time.RFC3339Nano, body.Expires)
	if err != nil || !time.Now().Before(expires) {
		return ErrRejected
	}
	hash := sha256.Sum256(raw)
	record = handoffRecord{Version: "runnerd-broker-handoff-v1", Name: p.Name, Boot: m.boot, Hash: hex.EncodeToString(hash[:]), Phase: "CREATING"}
	if err = m.ledger.writeRecord(root, id, record); err != nil {
		return err
	}
	if err = m.root.Mkdir(p.Name, 0700); err != nil {
		return err
	}
	if err = m.root.Chown(p.Name, m.uid, m.uid); err != nil {
		return err
	}
	dir, st, err := userDirectory(m.root, p.Name, m.uid)
	if err != nil {
		return err
	}
	defer dir.Close()
	file, err := dir.OpenFile("bootstrap.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(raw)
	if e := file.Chown(m.uid, m.uid); err == nil {
		err = e
	}
	if err == nil {
		err = file.Sync()
	}
	if e := file.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	if err = syncDirectory(dir); err != nil {
		return err
	}
	if err = syncDirectory(m.root); err != nil {
		return err
	}
	record.Device = uint64(st.Dev)
	record.Inode = st.Ino
	record.Phase = "READY"
	return m.ledger.writeRecord(root, id, record)
}
func (m *handoffManager) verify(p dockerengine.Plan, r handoffRecord) error {
	if r.Version != "runnerd-broker-handoff-v1" || r.Name != p.Name || r.Boot != m.boot || r.Phase != "READY" || !digest(r.Hash) {
		return ErrQuarantined
	}
	dir, st, err := userDirectory(m.root, p.Name, m.uid)
	if err != nil {
		return err
	}
	defer dir.Close()
	if uint64(st.Dev) != r.Device || st.Ino != r.Inode {
		return ErrQuarantined
	}
	raw, err := readUserFile(dir, "bootstrap.json", m.uid, 131072)
	if err != nil {
		return err
	}
	defer clear(raw)
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != r.Hash {
		return ErrQuarantined
	}
	return nil
}
func (m *handoffManager) Registration(p dockerengine.Plan) ([]byte, error) {
	root, err := m.ledger.records("handoffs")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var r handoffRecord
	if err = readRecord(root, handoffID(p.Name), &r); err != nil {
		return nil, err
	}
	dir, st, err := userDirectory(m.root, p.Name, m.uid)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	if r.Name != p.Name || r.Boot != m.boot || uint64(st.Dev) != r.Device || st.Ino != r.Inode {
		return nil, ErrQuarantined
	}
	return readUserFile(dir, "registered.json", m.uid, 8192)
}
func (m *handoffManager) Dispose(p dockerengine.Plan) error {
	root, err := m.ledger.records("handoffs")
	if err != nil {
		return err
	}
	defer root.Close()
	id := handoffID(p.Name)
	var r handoffRecord
	if err = readRecord(root, id, &r); err != nil {
		return err
	}
	if r.Version != "runnerd-broker-handoff-v1" || r.Name != p.Name || r.Boot != m.boot {
		return ErrQuarantined
	}
	if r.Phase == "DISPOSED" {
		return m.CheckDisposed(p)
	}
	if r.Phase != "READY" && r.Phase != "DISPOSING" {
		return ErrQuarantined
	}
	if r.Phase == "DISPOSING" && r.Device != 0 && r.Inode != 0 {
		if _, err = m.root.Lstat(p.Name); os.IsNotExist(err) {
			if err = syncDirectory(m.root); err != nil {
				return err
			}
			r.Phase = "DISPOSED"
			return m.ledger.writeRecord(root, id, r)
		}
	}
	dir, st, err := userDirectory(m.root, p.Name, m.uid)
	if err != nil {
		return ErrQuarantined
	}
	defer dir.Close()
	if uint64(st.Dev) != r.Device || st.Ino != r.Inode {
		return ErrQuarantined
	}
	f, err := dir.Open(".")
	if err != nil {
		return err
	}
	names, err := f.Readdirnames(3)
	f.Close()
	if err != nil && err != io.EOF {
		return err
	}
	for _, name := range names {
		if name != "bootstrap.json" && name != "registered.json" {
			return ErrQuarantined
		}
	}
	r.Phase = "DISPOSING"
	if err = m.ledger.writeRecord(root, id, r); err != nil {
		return err
	}
	for _, name := range names {
		raw, e := readUserFile(dir, name, m.uid, 131072)
		clear(raw)
		if e != nil {
			return e
		}
		if e = dir.Remove(name); e != nil {
			return e
		}
	}
	if err = syncDirectory(dir); err != nil {
		return err
	}
	if err = m.root.Remove(p.Name); err != nil {
		return err
	}
	if err = syncDirectory(m.root); err != nil {
		return err
	}
	r.Phase = "DISPOSED"
	return m.ledger.writeRecord(root, id, r)
}
func (m *handoffManager) CheckDisposed(p dockerengine.Plan) error {
	root, err := m.ledger.records("handoffs")
	if err != nil {
		return err
	}
	defer root.Close()
	var r handoffRecord
	if err = readRecord(root, handoffID(p.Name), &r); err != nil {
		return err
	}
	if r.Version != "runnerd-broker-handoff-v1" || r.Name != p.Name || r.Boot != m.boot || r.Phase != "DISPOSED" {
		return ErrQuarantined
	}
	if _, err = m.root.Lstat(p.Name); !errors.Is(err, os.ErrNotExist) {
		return ErrQuarantined
	}
	return syncDirectory(m.root)
}

// Empty handoff disposal is allowed only by the separately scoped cleanup
// operation, before any protected create intent exists.
func (m *handoffManager) DisposeUnstarted(p dockerengine.Plan) error {
	root, err := m.ledger.records("handoffs")
	if err != nil {
		return err
	}
	defer root.Close()
	var r handoffRecord
	err = readRecord(root, handoffID(p.Name), &r)
	if err == nil {
		return m.Dispose(p)
	}
	if !os.IsNotExist(err) {
		return err
	}
	if _, err = m.root.Lstat(p.Name); !os.IsNotExist(err) {
		return ErrQuarantined
	}
	if err = syncDirectory(m.root); err != nil {
		return err
	}
	return m.ledger.writeRecord(root, handoffID(p.Name), handoffRecord{Version: "runnerd-broker-handoff-v1", Name: p.Name, Boot: m.boot, Phase: "DISPOSED"})
}

// A changed boot proves old processes cannot retain the old volatile mount.
// The original durable handoff remains immutable. Any reappearing path blocks
// closure; boot recovery never recreates or deletes a new handoff directory.
func (m *handoffManager) BootAbsent(p dockerengine.Plan, originalBoot string, requireOwned bool) error {
	if originalBoot == "" || originalBoot == m.boot {
		return ErrQuarantined
	}
	root, err := m.ledger.records("handoffs")
	if err != nil {
		return err
	}
	defer root.Close()
	var record handoffRecord
	err = readRecord(root, handoffID(p.Name), &record)
	if err != nil && (!os.IsNotExist(err) || requireOwned) {
		return ErrQuarantined
	}
	if err == nil && (record.Version != "runnerd-broker-handoff-v1" || record.Name != p.Name || record.Boot != originalBoot || (record.Phase != "CREATING" && record.Phase != "READY" && record.Phase != "DISPOSING" && record.Phase != "DISPOSED")) {
		return ErrQuarantined
	}
	if _, err = m.root.Lstat(p.Name); !os.IsNotExist(err) {
		return ErrQuarantined
	}
	return syncDirectory(m.root)
}
