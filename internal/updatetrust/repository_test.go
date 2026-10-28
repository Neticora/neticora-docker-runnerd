//go:build linux

package updatetrust

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// Test keys are generated in memory and never provision production trust.
type testRepository struct {
	t                                  *testing.T
	dir, bundle, state, bootstrap, pin string
	now                                time.Time
	root                               *metadata.Metadata[metadata.RootType]
	keys                               map[string][]signature.SignerVerifier
	files                              map[string][]byte
	rev                                revocations
	release                            ReleaseManifest
	b                                  Bootstrap
}

func testWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func testJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newTestRoot(t *testing.T, now time.Time, version int64) (*metadata.Metadata[metadata.RootType], map[string][]signature.SignerVerifier) {
	t.Helper()
	r := metadata.Root(now.Add(24 * time.Hour))
	r.Signed.Version = version
	keys := map[string][]signature.SignerVerifier{}
	for _, role := range metadata.TOP_LEVEL_ROLE_NAMES {
		count := 1
		if role == metadata.ROOT {
			count = 2
			r.Signed.Roles[role].Threshold = 2
		}
		for i := 0; i < count; i++ {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := signature.LoadED25519SignerVerifier(priv)
			if err != nil {
				t.Fatal(err)
			}
			key, err := metadata.KeyFromPublicKey(pub)
			if err != nil {
				t.Fatal(err)
			}
			if err = r.Signed.AddKey(key, role); err != nil {
				t.Fatal(err)
			}
			keys[role] = append(keys[role], signer)
		}
	}
	for _, signer := range keys[metadata.ROOT] {
		if _, err := r.Sign(signer); err != nil {
			t.Fatal(err)
		}
	}
	return r, keys
}

func newTestRepository(t *testing.T) *testRepository {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	r := &testRepository{t: t, dir: dir, bundle: filepath.Join(dir, "bundle"), state: filepath.Join(dir, "state"), bootstrap: filepath.Join(dir, "bootstrap.json"), now: time.Now().UTC().Add(time.Second), files: map[string][]byte{}}
	r.root, r.keys = newTestRoot(t, r.now, 1)
	rootRaw, err := r.root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	r.b = Bootstrap{SchemaVersion: 1, RootID: "qualification", RootVersion: 1, RootSHA256: sha(rootRaw), Root: rootRaw,
		ValidFrom: r.now.Add(-time.Hour), ExpiresAt: r.now.Add(72 * time.Hour), MaxOfflineAgeSeconds: 3600,
		Profile: "local-qualification", Repository: repoURI, SourceRef: "refs/heads/main", Issuer: "https://token.actions.githubusercontent.com", Subject: repoURI + "/.github/workflows/release-candidate.yml@refs/heads/main"}
	r.writeBootstrap()
	r.files["runnerd-linux-amd64.tar.gz"] = []byte("unit-test-amd64-archive")
	r.files["runnerd-linux-arm64.tar.gz"] = []byte("unit-test-arm64-archive")
	r.files["sbom.spdx.json"] = []byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","dataLicense":"CC0-1.0","documentNamespace":"https://example.invalid/qualification","packages":[{"name":"runnerd","SPDXID":"SPDXRef-runnerd"}]}`)
	r.release = ReleaseManifest{SchemaVersion: 1, ArtifactClass: "foundation-candidate", Sequence: "1", SourceSHA: strings.Repeat("a", 40)}
	r.rev = revocations{SchemaVersion: 1, RootVersion: 1, IssuedAt: r.now, ExpiresAt: r.now.Add(time.Hour), KeyIDs: []string{}, SHA256: []string{}}
	r.publish(1)
	if err = Initialize(r.bootstrap, r.pin, r.state, true); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *testRepository) writeBootstrap() {
	raw := testJSON(r.t, r.b)
	testWrite(r.t, r.bootstrap, raw)
	r.pin = sha(raw)
}

func (r *testRepository) publish(version int64) {
	t := r.t
	var checksums []string
	for _, name := range []string{"runnerd-linux-amd64.tar.gz", "runnerd-linux-arm64.tar.gz", "sbom.spdx.json"} {
		checksums = append(checksums, sha(r.files[name])+"  ./"+name)
	}
	sort.Strings(checksums)
	r.files["SHA256SUMS"] = []byte(strings.Join(checksums, "\n") + "\n")
	var p provenance
	p.Type = "https://in-toto.io/Statement/v1"
	p.PredicateType = "https://slsa.dev/provenance/v1"
	p.Predicate.BuildDefinition.BuildType = repoURI + "/packaging/local-qualification/v1"
	if r.b.Profile == "github-candidate" {
		p.Predicate.BuildDefinition.BuildType = "https://actions.github.io/buildtypes/workflow/v1"
	}
	p.Predicate.BuildDefinition.ExternalParameters = json.RawMessage(`{"qualificationOnly":true}`)
	p.Predicate.BuildDefinition.InternalParameters = json.RawMessage(`{}`)
	p.Predicate.RunDetails = json.RawMessage(`{"builder":{"id":"local-qualification"}}`)
	dependency := struct {
		URI    string            `json:"uri"`
		Digest map[string]string `json:"digest"`
	}{repoURI, map[string]string{"gitCommit": r.release.SourceSHA}}
	p.Predicate.BuildDefinition.ResolvedDependencies = append(p.Predicate.BuildDefinition.ResolvedDependencies, dependency)
	for _, name := range []string{"runnerd-linux-amd64.tar.gz", "runnerd-linux-arm64.tar.gz", "sbom.spdx.json", "SHA256SUMS"} {
		p.Subject = append(p.Subject, struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		}{name, map[string]string{"sha256": sha(r.files[name])}})
	}
	r.files["provenance.json"] = testJSON(t, p)
	r.release.Files = map[string]string{}
	for name, raw := range r.files {
		if name != "release.json" && name != "revocations.json" {
			r.release.Files[name] = sha(raw)
		}
	}
	r.files["release.json"] = testJSON(t, r.release)
	r.rev.RootVersion = r.root.Signed.Version
	r.files["revocations.json"] = testJSON(t, r.rev)
	targets := metadata.Targets(r.now.Add(2 * time.Hour))
	targets.Signed.Version = version
	for name, raw := range r.files {
		info, err := metadata.TargetFile().FromBytes(name, raw, "sha256")
		if err != nil {
			t.Fatal(err)
		}
		targets.Signed.Targets[name] = info
		testWrite(t, filepath.Join(r.bundle, "targets", name), raw)
	}
	for _, key := range r.keys[metadata.TARGETS] {
		if _, err := targets.Sign(key); err != nil {
			t.Fatal(err)
		}
	}
	targetRaw, err := targets.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := metadata.Snapshot(r.now.Add(2 * time.Hour))
	snapshot.Signed.Version = version
	digest := sha256Bytes(targetRaw)
	snapshot.Signed.Meta["targets.json"] = &metadata.MetaFiles{Version: version, Length: int64(len(targetRaw)), Hashes: metadata.Hashes{"sha256": digest}}
	for _, key := range r.keys[metadata.SNAPSHOT] {
		if _, err = snapshot.Sign(key); err != nil {
			t.Fatal(err)
		}
	}
	snapshotRaw, err := snapshot.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := metadata.Timestamp(r.now.Add(2 * time.Hour))
	timestamp.Signed.Version = version
	timestamp.Signed.Meta["snapshot.json"] = &metadata.MetaFiles{Version: version, Length: int64(len(snapshotRaw)), Hashes: metadata.Hashes{"sha256": sha256Bytes(snapshotRaw)}}
	for _, key := range r.keys[metadata.TIMESTAMP] {
		if _, err = timestamp.Sign(key); err != nil {
			t.Fatal(err)
		}
	}
	timestampRaw, err := timestamp.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"targets": targetRaw, "snapshot": snapshotRaw, "timestamp": timestampRaw} {
		testWrite(t, filepath.Join(r.bundle, "metadata", name+".json"), raw)
	}
}

func sha256Bytes(raw []byte) []byte { sum := sha256.Sum256(raw); return sum[:] }

func (r *testRepository) verify() error {
	result, err := verifyAt(r.bootstrap, r.pin, r.state, r.bundle, r.release.SourceSHA, true, r.now)
	if err == nil && (result.ProductionQualified || result.VerificationProfile != "local-qualification" || result.ArtifactCount != 2) {
		r.t.Fatal("qualification promoted to production")
	}
	return err
}

func (r *testRepository) rotate() []string {
	oldKeys := r.keys[metadata.ROOT]
	oldIDs := append([]string{}, r.root.Signed.Roles[metadata.ROOT].KeyIDs...)
	r.root, r.keys = newTestRoot(r.t, r.now, r.root.Signed.Version+1)
	for _, key := range oldKeys {
		if _, err := r.root.Sign(key); err != nil {
			r.t.Fatal(err)
		}
	}
	raw, err := r.root.ToBytes(false)
	if err != nil {
		r.t.Fatal(err)
	}
	testWrite(r.t, filepath.Join(r.bundle, "metadata", fmt.Sprintf("%d.root.json", r.root.Signed.Version)), raw)
	return oldIDs
}
