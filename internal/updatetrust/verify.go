package updatetrust

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

type revocations struct {
	SchemaVersion int       `json:"schemaVersion"`
	RootVersion   int64     `json:"rootVersion"`
	IssuedAt      time.Time `json:"issuedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	KeyIDs        []string  `json:"keyIds"`
	SHA256        []string  `json:"sha256"`
}

type Result struct {
	RootVersion         int64             `json:"rootVersion"`
	SourceSHA           string            `json:"sourceSha"`
	ArtifactCount       int               `json:"artifactCount"`
	VerificationProfile string            `json:"verificationProfile"`
	ProductionQualified bool              `json:"productionQualified"`
	ArtifactSHA256      map[string]string `json:"artifactSha256"`
}

// Verify uses only local files. The independently supplied pin is never read
// from the update bundle. Trust/anti-rollback state may advance even when the
// requested artifact is rejected, so a revoked artifact cannot undo revocation.
func Verify(bootstrapPath, pin, stateDir, bundleDir, reviewedSHA string, qualificationOnly bool) (Result, error) {
	return verifyAt(bootstrapPath, pin, stateDir, bundleDir, reviewedSHA, qualificationOnly, time.Now().UTC())
}

func verifyAt(bootstrapPath, pin, stateDir, bundleDir, reviewedSHA string, qualificationOnly bool, now time.Time) (Result, error) {
	var result Result
	if !commitPattern.MatchString(reviewedSHA) {
		return result, errors.New("reviewed source commit required")
	}
	b, err := loadBootstrap(bootstrapPath, pin, now)
	if err != nil {
		return result, err
	}
	if (b.Profile == "local-qualification") != qualificationOnly {
		return result, errors.New("trust profile and requested operation differ")
	}
	state, err := hostfs.OpenState(stateDir)
	if err != nil {
		return result, err
	}
	defer state.Close()
	lock, err := hostfs.Lock(state)
	if err != nil {
		return result, err
	}
	defer lock.Close()
	c, err := loadCheckpoint(stateDir, pin)
	if err != nil {
		return result, err
	}
	if now.Before(c.LastSeen) {
		return result, errors.New("clock rollback rejected")
	}
	trusted, err := trustedmetadata.New(c.Root)
	if err != nil || trusted.Root.Signed.Version < b.RootVersion {
		return result, errors.New("stored root rejected")
	}
	trusted.RefTime = now
	if err = checkRoles(trusted, b.Profile); err != nil {
		return result, err
	}
	if err = rejectRevokedKeys(trusted, c); err != nil {
		return result, err
	}
	if !filepath.IsAbs(bundleDir) || filepath.Clean(bundleDir) != bundleDir {
		return result, errors.New("invalid bundle directory")
	}
	for _, protected := range []string{bootstrapPath, stateDir} {
		rel, relErr := filepath.Rel(bundleDir, protected)
		if relErr != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return result, errors.New("bootstrap and state must be outside the untrusted bundle")
		}
	}
	bundle, err := os.OpenRoot(bundleDir)
	if err != nil {
		return result, errors.New("bundle unavailable")
	}
	defer bundle.Close()
	// Sequential old-and-new threshold signatures are checked by go-tuf. Persist
	// each authenticated root immediately, including when later metadata fails.
	for rotations := 0; ; rotations++ {
		name := fmt.Sprintf("metadata/%d.root.json", trusted.Root.Signed.Version+1)
		_, statErr := bundle.Lstat(name)
		if os.IsNotExist(statErr) {
			break
		}
		if statErr != nil || rotations >= 64 {
			return result, errors.New("root rotation bound or file rejected")
		}
		raw, err := readFile(bundle, name, maxJSON)
		if err != nil {
			return result, err
		}
		var object map[string]any
		if strictJSON(raw, &object) != nil {
			return result, errors.New("invalid root JSON")
		}
		oldRoles := trusted.Root.Signed.Roles
		if _, err = trusted.UpdateRoot(raw); err != nil {
			return result, errors.New("root rotation signature or sequence rejected")
		}
		if err = checkRoles(trusted, b.Profile); err != nil {
			return result, err
		}
		if err = rejectRevokedKeys(trusted, c); err != nil {
			return result, err
		}
		// TUF resets metadata rollback counters when its signing keys are rotated;
		// this permits recovery from compromised-key version fast-forward attacks.
		for _, role := range []string{metadata.TIMESTAMP, metadata.SNAPSHOT, metadata.TARGETS} {
			old, next := oldRoles[role], trusted.Root.Signed.Roles[role]
			if old == nil || next == nil {
				return result, errors.New("missing TUF role")
			}
			oldJSON, _ := json.Marshal(old)
			nextJSON, _ := json.Marshal(next)
			if string(oldJSON) != string(nextJSON) {
				delete(c.Versions, role)
				delete(c.Digests, role)
			}
		}
		c.Root = raw
		c.LastSeen = now
		if err = saveCheckpoint(state, c); err != nil {
			return result, err
		}
	}
	if err = rejectRevokedKeys(trusted, c); err != nil {
		return result, err
	}
	for _, role := range []string{metadata.TIMESTAMP, metadata.SNAPSHOT, metadata.TARGETS} {
		raw, err := readFile(bundle, "metadata/"+role+".json", maxJSON)
		if err != nil {
			return result, err
		}
		var envelope struct {
			Signed struct {
				Version int64 `json:"version"`
			} `json:"signed"`
		}
		// Metadata permits extension fields. Validate raw Unicode/duplicate keys
		// independently, then let go-tuf perform type, signature and link validation.
		var object map[string]any
		if strictJSON(raw, &object) != nil || json.Unmarshal(raw, &envelope) != nil || envelope.Signed.Version < 1 {
			return result, errors.New("invalid TUF metadata JSON")
		}
		version := envelope.Signed.Version
		if version < c.Versions[role] || (version == c.Versions[role] && sha(raw) != c.Digests[role]) {
			return result, errors.New("metadata rollback or same-version equivocation rejected")
		}
		switch role {
		case metadata.TIMESTAMP:
			_, err = trusted.UpdateTimestamp(raw)
		case metadata.SNAPSHOT:
			_, err = trusted.UpdateSnapshot(raw, false)
		case metadata.TARGETS:
			_, err = trusted.UpdateTargets(raw)
		}
		if err != nil {
			return result, errors.New("TUF signature, expiry or metadata binding rejected")
		}
		c.Versions[role], c.Digests[role], c.LastSeen = version, sha(raw), now
		if err = saveCheckpoint(state, c); err != nil {
			return result, err
		}
	}
	targets := trusted.Targets[metadata.TARGETS]
	if targets == nil || targets.Signed.Delegations != nil {
		return result, errors.New("delegated or missing targets unsupported")
	}
	v := verifier{bootstrap: b, bundle: bundle, targets: targets.Signed.Targets, now: now}
	raw, err := v.targetJSON("revocations.json")
	if err != nil {
		return result, err
	}
	var rev revocations
	if strictJSON(raw, &rev) != nil || rev.SchemaVersion != 1 || rev.RootVersion != trusted.Root.Signed.Version ||
		rev.IssuedAt.IsZero() || rev.IssuedAt.After(now) || !rev.ExpiresAt.After(rev.IssuedAt) || len(rev.KeyIDs)+len(rev.SHA256) > 4096 {
		return result, errors.New("invalid signed revocation policy")
	}
	for _, id := range rev.KeyIDs {
		if !digestPattern.MatchString(id) {
			return result, errors.New("invalid revoked key identifier")
		}
		c.RevokedKeys[id] = true
	}
	for _, digest := range rev.SHA256 {
		if !digestPattern.MatchString(digest) {
			return result, errors.New("invalid revoked artifact digest")
		}
		c.RevokedFiles[digest] = true
	}
	// Revocations are cumulative and durable before artifact checking, even if
	// an old or stale candidate supplied alongside newer trust is rejected.
	if err = saveCheckpoint(state, c); err != nil {
		return result, err
	}
	if err = rejectRevokedKeys(trusted, c); err != nil {
		return result, err
	}
	if !rev.ExpiresAt.After(now) || now.Sub(rev.IssuedAt) > time.Duration(b.MaxOfflineAgeSeconds)*time.Second {
		return result, errors.New("offline trust expired or freshness bound exceeded")
	}
	v.revoked = c.RevokedFiles
	v.revokedKeys = c.RevokedKeys
	release, manifestDigest, err := v.verifyRelease(reviewedSHA)
	if err != nil {
		return result, err
	}
	sequence, err := strconv.ParseUint(release.Sequence, 10, 64)
	if err != nil || sequence == 0 || strconv.FormatUint(sequence, 10) != release.Sequence {
		return result, errors.New("invalid release sequence")
	}
	previous := uint64(0)
	if c.ReleaseSequence != "" {
		previous, err = strconv.ParseUint(c.ReleaseSequence, 10, 64)
		if err != nil {
			return result, errors.New("invalid release checkpoint")
		}
	}
	if sequence < previous || (sequence == previous && manifestDigest != c.ReleaseDigest) {
		return result, errors.New("release rollback or equivocation rejected")
	}
	artifacts := map[string]string{}
	for _, name := range []string{"runnerd-linux-amd64.tar.gz", "runnerd-linux-arm64.tar.gz"} {
		if err = v.stageArtifact(state, name, release.Files[name]); err != nil {
			return result, err
		}
		artifacts[name] = release.Files[name]
	}
	c.ReleaseSequence, c.ReleaseDigest = release.Sequence, manifestDigest
	if err = saveCheckpoint(state, c); err != nil {
		return result, err
	}
	return Result{RootVersion: trusted.Root.Signed.Version, SourceSHA: reviewedSHA, ArtifactCount: 2, VerificationProfile: b.Profile, ProductionQualified: false, ArtifactSHA256: artifacts}, nil
}

func rejectRevokedKeys(trusted *trustedmetadata.TrustedMetadata, c checkpoint) error {
	for _, role := range trusted.Root.Signed.Roles {
		for _, id := range role.KeyIDs {
			if c.RevokedKeys[id] {
				return errors.New("revoked trust key rejected")
			}
		}
	}
	return nil
}
