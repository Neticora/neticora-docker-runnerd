package updatetrust

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

// Reanchor renews an independently pinned bootstrap without resetting rollback
// or revocation state. A changed root must additionally have the old and new
// threshold signatures. This is an explicit administrative operation, not an
// artifact-supplied automatic trust change or a revoked-key recovery bypass.
func Reanchor(oldPath, oldPin, newPath, newPin, stateDir string, qualificationOnly bool) error {
	now := time.Now().UTC()
	// Expiry blocks artifact acceptance, not verification of the old pin during
	// explicit renewal. New independent material must be valid at the real time.
	raw, err := hostfs.ReadPrivate(oldPath, maxJSON)
	if err != nil {
		return err
	}
	var oldHeader Bootstrap
	if strictJSON(raw, &oldHeader) != nil {
		return errors.New("old bootstrap invalid")
	}
	oldTime := now
	if !oldHeader.ExpiresAt.After(now) {
		oldTime = oldHeader.ExpiresAt.Add(-time.Nanosecond)
	}
	old, err := loadBootstrap(oldPath, oldPin, oldTime)
	if err != nil {
		return err
	}
	next, err := loadBootstrap(newPath, newPin, now)
	if err != nil {
		return err
	}
	if old.RootID != next.RootID || old.Profile != next.Profile || (next.Profile == "local-qualification") != qualificationOnly || old.Repository != next.Repository || old.RepositoryID != next.RepositoryID || old.OwnerID != next.OwnerID || old.Issuer != next.Issuer || old.Subject != next.Subject || old.SourceRef != next.SourceRef {
		return errors.New("bootstrap renewal cannot change the trust domain or signer policy")
	}
	state, err := hostfs.OpenState(stateDir)
	if err != nil {
		return err
	}
	defer state.Close()
	lock, err := hostfs.Lock(state)
	if err != nil {
		return err
	}
	defer lock.Close()
	c, err := loadCheckpoint(stateDir, oldPin)
	if err != nil {
		return err
	}
	if now.Before(c.LastSeen) {
		return errors.New("clock rollback rejected")
	}
	trusted, err := trustedmetadata.New(c.Root)
	if err != nil {
		return errors.New("stored root rejected")
	}
	if err = rejectRevokedKeys(trusted, c); err != nil {
		return err
	}
	newRoot, err := trustedmetadata.New(next.Root)
	if err != nil || newRoot.Root.Signed.IsExpired(now) {
		return errors.New("new root expired or invalid")
	}
	if newRoot.Root.Signed.Version == trusted.Root.Signed.Version {
		a, _ := json.Marshal(newRoot.Root.Signed)
		b, _ := json.Marshal(trusted.Root.Signed)
		if !bytes.Equal(a, b) {
			return errors.New("same-version root equivocation rejected")
		}
	} else {
		oldRoles := trusted.Root.Signed.Roles
		if _, err = trusted.UpdateRoot(next.Root); err != nil {
			return errors.New("renewal root lacks sequential old-and-new threshold authorization")
		}
		// A new root can recover metadata epochs, while release rollback and
		// cumulative revocations stay fenced across independent bootstrap renewal.
		for role := range c.Versions {
			oldRole, _ := json.Marshal(oldRoles[role])
			nextRole, _ := json.Marshal(newRoot.Root.Signed.Roles[role])
			if !bytes.Equal(oldRole, nextRole) {
				delete(c.Versions, role)
				delete(c.Digests, role)
			}
		}
	}
	if err = checkRoles(newRoot, next.Profile); err != nil {
		return err
	}
	if err = rejectRevokedKeys(newRoot, c); err != nil {
		return err
	}
	c.Root, c.BootstrapPin, c.LastSeen = next.Root, newPin, now
	return saveCheckpoint(state, c)
}
