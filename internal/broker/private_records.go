package broker

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
)

// All callers hold the installation ledger mutex and its exclusive process lock.
// Supplemental records do not change the existing append-only receipt format.
func (l *Ledger) records(name string) (*os.Root, error) {
	if l.failed || (name != "challenges" && name != "resources" && name != "handoffs" && name != "boot-challenges" && name != "boot-recoveries" && name != "boot-history") {
		return nil, ErrRejected
	}
	if err := l.root.Mkdir(name, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	info, err := l.root.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !ownedRecord(info) {
		return nil, ErrRejected
	}
	root, err := l.root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	// Persist the directory itself before recording obligations within it.
	f, err := l.root.Open(".")
	if err == nil {
		err = f.Sync()
		_ = f.Close()
	}
	if err != nil {
		root.Close()
		l.failed = true
		return nil, err
	}
	return root, nil
}

func readRecord(root *os.Root, id string, value any) error {
	if !digest(id) {
		return ErrRejected
	}
	info, err := root.Lstat(id + ".json")
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > MaxMessage || !ownedRecord(info) {
		return ErrRejected
	}
	raw, err := root.ReadFile(id + ".json")
	if err != nil {
		return err
	}
	return decode(raw, value)
}

func (l *Ledger) writeRecord(root *os.Root, id string, value any) error {
	if !digest(id) || l.failed {
		return ErrRejected
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > MaxMessage {
		return ErrRejected
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := "pending-" + hex.EncodeToString(nonce[:])
	f, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err == nil {
		err = root.Rename(temporary, id+".json")
	}
	if err == nil {
		dir, e := root.Open(".")
		if e == nil {
			e = dir.Sync()
			_ = dir.Close()
		}
		err = e
	}
	if err != nil {
		l.failed = true
	}
	// Preserve partial files after errors for reconciliation, never erase evidence.
	return err
}
