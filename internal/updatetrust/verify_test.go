//go:build linux

package updatetrust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestOfflineSignedReleaseAndProfileSeparation(t *testing.T) {
	r := newTestRepository(t)
	if err := r.verify(); err != nil {
		t.Fatal(err)
	}
	if err := r.verify(); err != nil {
		t.Fatal("rechecking same signed release failed:", err)
	}
	if _, err := Verify(r.bootstrap, r.pin, r.state, r.bundle, r.release.SourceSHA, false); err == nil {
		t.Fatal("qualification root authorized non-qualification verification")
	}
	if err := Initialize(r.bootstrap, r.pin, r.state, true); err == nil {
		t.Fatal("existing trust state reset")
	}
}

func TestBootstrapMissingTamperedUnsafeAndExpired(t *testing.T) {
	for _, kind := range []string{"missing", "wrong-pin", "unsafe-mode", "expired", "future", "source", "missing-checkpoint"} {
		t.Run(kind, func(t *testing.T) {
			r := newTestRepository(t)
			switch kind {
			case "missing":
				if err := os.Remove(r.bootstrap); err != nil {
					t.Fatal(err)
				}
			case "wrong-pin":
				r.pin = strings.Repeat("0", 64)
			case "unsafe-mode":
				if err := os.Chmod(r.bootstrap, 0644); err != nil {
					t.Fatal(err)
				}
			case "expired":
				r.now = r.b.ExpiresAt.Add(time.Second)
			case "future":
				r.now = r.b.ValidFrom.Add(-time.Second)
			case "source":
				r.release.SourceSHA = strings.Repeat("b", 40)
			case "missing-checkpoint":
				if err := os.Remove(filepath.Join(r.state, "checkpoint.json")); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.verify(); err == nil {
				t.Fatal("unsafe bootstrap/checkpoint accepted")
			}
		})
	}
}

func TestOfflineFreshnessCannotBeExtendedByReverification(t *testing.T) {
	r := newTestRepository(t)
	if err := r.verify(); err != nil {
		t.Fatal(err)
	}
	r.now = r.now.Add(59 * time.Minute)
	if err := r.verify(); err != nil {
		t.Fatal(err)
	}
	r.now = r.now.Add(2 * time.Minute)
	if err := r.verify(); err == nil {
		t.Fatal("reverification extended signed offline lifetime")
	}
	// A genuinely refreshed, newly signed metadata generation restores freshness.
	r.rev.IssuedAt = r.now
	r.rev.ExpiresAt = r.now.Add(time.Hour)
	r.release.Sequence = "2"
	r.publish(2)
	if err := r.verify(); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataRollbackEquivocationAndClockRollback(t *testing.T) {
	for _, kind := range []string{"rollback", "equivocation", "clock"} {
		t.Run(kind, func(t *testing.T) {
			r := newTestRepository(t)
			if err := r.verify(); err != nil {
				t.Fatal(err)
			}
			old, err := os.ReadFile(filepath.Join(r.bundle, "metadata/timestamp.json"))
			if err != nil {
				t.Fatal(err)
			}
			r.now = r.now.Add(time.Minute)
			r.rev.IssuedAt = r.now
			r.release.Sequence = "2"
			r.publish(2)
			if err = r.verify(); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "rollback":
				testWrite(t, filepath.Join(r.bundle, "metadata/timestamp.json"), old)
			case "equivocation":
				r.rev.SHA256 = []string{strings.Repeat("b", 64)}
				r.publish(2)
			case "clock":
				r.now = r.now.Add(-time.Minute)
			}
			if err = r.verify(); err == nil {
				t.Fatal("rollback/equivocation accepted")
			}
		})
	}
}

func TestRevocationSurvivesRejectedCandidateAndNewEmptyList(t *testing.T) {
	r := newTestRepository(t)
	if err := r.verify(); err != nil {
		t.Fatal(err)
	}
	digest := r.release.Files["runnerd-linux-amd64.tar.gz"]
	r.rev.SHA256 = []string{digest}
	r.publish(2)
	if err := r.verify(); err == nil {
		t.Fatal("revoked artifact accepted")
	}
	c, err := loadCheckpoint(r.state, r.pin)
	if err != nil || !c.RevokedFiles[digest] {
		t.Fatal("revocation lost on rejection")
	}
	r.rev.SHA256 = []string{}
	r.publish(3)
	if err := r.verify(); err == nil {
		t.Fatal("empty new revocation list restored revoked artifact")
	}
}

func TestRootRotationRequiresBothThresholdsAndRetainsRevocation(t *testing.T) {
	r := newTestRepository(t)
	if err := r.verify(); err != nil {
		t.Fatal(err)
	}
	oldIDs := r.rotate()
	r.rev.KeyIDs = oldIDs
	r.release.Sequence = "2"
	r.publish(2)
	if err := r.verify(); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := loadCheckpoint(r.state, r.pin)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range oldIDs {
		if !checkpoint.RevokedKeys[id] {
			t.Fatal("old root revocation missing")
		}
	}
	// The old bootstrap remains pinned; its original root need not be replaced.
	if checkpoint.BootstrapPin != r.pin {
		t.Fatal("rotation replaced independent bootstrap pin")
	}
	// A self-signed next root without the old threshold must fail.
	next, _ := newTestRoot(t, r.now, 3)
	raw, err := next.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	testWrite(t, filepath.Join(r.bundle, "metadata/3.root.json"), raw)
	if err = r.verify(); err == nil {
		t.Fatal("self-authorized replacement root accepted")
	}
}

func TestRevokedActiveKeyCannotAuthorizeRecoveryRotation(t *testing.T) {
	r := newTestRepository(t)
	r.rev.KeyIDs = append([]string{}, r.root.Signed.Roles[metadata.ROOT].KeyIDs...)
	r.publish(2)
	if err := r.verify(); err == nil {
		t.Fatal("revoked active root accepted")
	}
	r.rotate()
	r.publish(3)
	if err := r.verify(); err == nil {
		t.Fatal("revoked root authorized its own recovery")
	}
}

func TestTamperedArtifactsMetadataSBOMChecksumsAndProvenance(t *testing.T) {
	for _, name := range []string{"runnerd-linux-amd64.tar.gz", "runnerd-linux-arm64.tar.gz", "sbom.spdx.json", "SHA256SUMS", "provenance.json", "release.json", "revocations.json", "metadata/targets.json"} {
		t.Run(name, func(t *testing.T) {
			r := newTestRepository(t)
			path := filepath.Join(r.bundle, "targets", name)
			if strings.HasPrefix(name, "metadata/") {
				path = filepath.Join(r.bundle, name)
			}
			testWrite(t, path, []byte("canary-secret-do-not-print"))
			if err := r.verify(); err == nil || strings.Contains(err.Error(), "canary-secret") {
				t.Fatal("tamper accepted or disclosed")
			}
		})
	}
}

func TestSignedMalformedSPDXAndReleaseRollback(t *testing.T) {
	r := newTestRepository(t)
	r.files["sbom.spdx.json"] = []byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`)
	r.publish(2)
	if err := r.verify(); err == nil {
		t.Fatal("signed but malformed SBOM accepted")
	}
	r = newTestRepository(t)
	r.release.Sequence = "2"
	r.publish(2)
	if err := r.verify(); err != nil {
		t.Fatal(err)
	}
	r.release.Sequence = "1"
	r.publish(3)
	if err := r.verify(); err == nil {
		t.Fatal("new metadata permitted release sequence rollback")
	}
}

func TestExpiredMetadataAndSignedRoot(t *testing.T) {
	for _, kind := range []string{"timestamp", "root"} {
		t.Run(kind, func(t *testing.T) {
			r := newTestRepository(t)
			if kind == "root" {
				r.now = r.now.Add(25 * time.Hour)
			} else {
				r.now = r.now.Add(3 * time.Hour)
			}
			if err := r.verify(); err == nil {
				t.Fatal("expired trust accepted")
			}
		})
	}
}

func TestDuplicateBootstrapJSONAndSymlinkAreRejected(t *testing.T) {
	r := newTestRepository(t)
	raw, err := os.ReadFile(r.bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append([]byte(`{"schemaVersion":1,`), raw[1:]...)
	testWrite(t, r.bootstrap, duplicate)
	r.pin = sha(duplicate)
	if err = r.verify(); err == nil {
		t.Fatal("duplicate bootstrap field accepted")
	}
	testWrite(t, r.bootstrap, raw)
	r.pin = sha(raw)
	alias := filepath.Join(r.dir, "bootstrap-alias.json")
	if err = os.Symlink(r.bootstrap, alias); err != nil {
		t.Fatal(err)
	}
	r.bootstrap = alias
	if err = r.verify(); err == nil {
		t.Fatal("symlink bootstrap accepted")
	}
}

func TestGitHubProfileNeverFallsBackToQualification(t *testing.T) {
	r := newTestRepository(t)
	// This is deliberately not a GitHub-signed candidate. Even valid TUF metadata
	// cannot substitute for missing Sigstore certificate/transparency evidence.
	r.b.Profile = "github-candidate"
	r.b.SigstoreRootSHA256 = sha([]byte(`{}`))
	r.b.RepositoryID = "123"
	r.b.OwnerID = "456"
	r.writeBootstrap()
	r.state = filepath.Join(r.dir, "github-state")
	if err := Initialize(r.bootstrap, r.pin, r.state, false); err != nil {
		t.Fatal(err)
	}
	r.files["provenance.sigstore.json"] = []byte(`{}`)
	r.files["sigstore-trusted-root.json"] = []byte(`{}`)
	r.publish(2)
	if _, err := verifyAt(r.bootstrap, r.pin, r.state, r.bundle, r.release.SourceSHA, false, r.now); err == nil {
		t.Fatal("missing GitHub signature accepted")
	}
	if _, err := verifyAt(r.bootstrap, r.pin, r.state, r.bundle, r.release.SourceSHA, true, r.now); err == nil {
		t.Fatal("GitHub profile downgraded to local qualification")
	}
}
