package updatetrust

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

type checkpoint struct {
	SchemaVersion   int               `json:"schemaVersion"`
	BootstrapPin    string            `json:"bootstrapPin"`
	Root            json.RawMessage   `json:"root"`
	Versions        map[string]int64  `json:"versions"`
	Digests         map[string]string `json:"digests"`
	RevokedKeys     map[string]bool   `json:"revokedKeys"`
	RevokedFiles    map[string]bool   `json:"revokedFiles"`
	LastSeen        time.Time         `json:"lastSeen"`
	ReleaseSequence string            `json:"releaseSequence"`
	ReleaseDigest   string            `json:"releaseDigest"`
}

// Initialize creates a new protected anti-rollback store only. Existing state
// is never reset, adopted or erased. The bootstrap pin must come from outside
// the update bundle. The parent directory must already be trusted/provisioned.
func Initialize(bootstrapPath, pin, stateDir string, qualificationOnly bool) error {
	now := time.Now().UTC()
	b, err := loadBootstrap(bootstrapPath, pin, now)
	if err != nil {
		return err
	}
	if (b.Profile == "local-qualification") != qualificationOnly {
		return errors.New("trust profile and requested operation differ")
	}
	rootMetadata, err := trustedmetadata.New(b.Root)
	if err != nil || rootMetadata.Root.Signed.IsExpired(now) {
		return errors.New("initial trust root expired")
	}
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return errors.New("invalid trust state path")
	}
	if err = hostfs.CheckAncestors(filepath.Dir(stateDir)); err != nil {
		return err
	}
	if err = os.Mkdir(stateDir, 0700); err != nil {
		return errors.New("trust state exists or cannot be created")
	}
	root, err := hostfs.OpenState(stateDir)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := hostfs.Lock(root)
	if err != nil {
		return err
	}
	defer lock.Close()
	c := checkpoint{SchemaVersion: 1, BootstrapPin: pin, Root: b.Root,
		Versions: map[string]int64{}, Digests: map[string]string{},
		RevokedKeys: map[string]bool{}, RevokedFiles: map[string]bool{}, LastSeen: now}
	return saveCheckpoint(root, c)
}

func loadCheckpoint(stateDir, pin string) (checkpoint, error) {
	var c checkpoint
	data, err := hostfs.ReadPrivate(filepath.Join(stateDir, "checkpoint.json"), maxJSON)
	if err != nil {
		return c, errors.New("trust checkpoint missing or unsafe; explicit recovery required")
	}
	if err = strictJSON(data, &c); err != nil {
		return c, err
	}
	if c.SchemaVersion != 1 || c.BootstrapPin != pin || c.Versions == nil || c.Digests == nil ||
		c.RevokedKeys == nil || c.RevokedFiles == nil || c.LastSeen.IsZero() {
		return c, errors.New("trust checkpoint invalid")
	}
	return c, nil
}

func saveCheckpoint(root *os.Root, c checkpoint) error {
	data, err := json.Marshal(c)
	if err != nil || len(data) > maxJSON {
		return errors.New("trust checkpoint exceeds bound")
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return err
	}
	name := ".checkpoint-" + hex.EncodeToString(random[:])
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create trust checkpoint")
	}
	defer root.Remove(name)
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if errors.Join(writeErr, syncErr, closeErr) != nil {
		return errors.New("cannot persist trust checkpoint")
	}
	if err = root.Rename(name, "checkpoint.json"); err != nil {
		return errors.New("cannot activate trust checkpoint")
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return errors.New("cannot sync trust state directory")
	}
	return nil
}
