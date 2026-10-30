package updatetrust

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

// stageArtifact copies from a held descriptor and rehashes while copying. The
// returned content-addressed file is private to the trust-store owner. Installers
// must use that snapshot, never reopen the untrusted bundle after verification.
func (v *verifier) stageArtifact(state *os.Root, name, digest string) error {
	final := "verified-" + digest + ".tar.gz"
	if _, err := state.Lstat(final); err == nil {
		f, err := openRegular(state, final)
		if err != nil {
			return errors.New("verified snapshot unsafe")
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != v.targets[name].Length {
			return errors.New("verified snapshot metadata rejected")
		}
		h := sha256.New()
		if _, err = io.Copy(h, io.LimitReader(f, v.targets[name].Length+1)); err != nil || hex.EncodeToString(h.Sum(nil)) != digest {
			return errors.New("verified snapshot corrupted; preserving for inspection")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return errors.New("cannot inspect verified snapshot")
	}
	source, err := openRegular(v.bundle, "targets/"+name)
	if err != nil {
		return errors.New("artifact staging source unavailable")
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != v.targets[name].Length {
		return errors.New("artifact staging source rejected")
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return err
	}
	temporary := ".stage-" + hex.EncodeToString(random[:])
	f, err := state.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot stage verified artifact")
	}
	defer state.Remove(temporary)
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(source, v.targets[name].Length+1))
	syncErr := f.Sync()
	closeErr := f.Close()
	if errors.Join(copyErr, syncErr, closeErr) != nil || n != v.targets[name].Length || hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("artifact changed during staging")
	}
	if err = state.Rename(temporary, final); err != nil {
		return errors.New("cannot activate verified snapshot")
	}
	return nil // The subsequent checkpoint commit also fsyncs the shared directory.
}
