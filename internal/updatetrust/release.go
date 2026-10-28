package updatetrust

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

const repoURI = "https://github.com/Neticora/neticora-docker-runnerd"

// ReleaseManifest is a TUF-authenticated release set, not authority to execute
// jobs or install software. Checksums and provenance are themselves targets.
type ReleaseManifest struct {
	SchemaVersion       int               `json:"schemaVersion"`
	ArtifactClass       string            `json:"artifactClass"`
	ProductionQualified bool              `json:"productionQualified"`
	Sequence            string            `json:"sequence"`
	SourceSHA           string            `json:"sourceSha"`
	Files               map[string]string `json:"files"`
}

type verifier struct {
	bootstrap   Bootstrap
	bundle      *os.Root
	targets     map[string]*metadata.TargetFiles
	revoked     map[string]bool
	revokedKeys map[string]bool
	now         time.Time
}

func (v *verifier) target(name string, limit int64) ([]byte, error) {
	info := v.targets[name]
	if !namePattern.MatchString(name) || info == nil || info.Length < 0 || info.Length > limit || len(info.Hashes["sha256"]) != 32 {
		return nil, errors.New("required target or SHA-256 binding missing")
	}
	if v.revoked[hex.EncodeToString(info.Hashes["sha256"])] {
		return nil, errors.New("revoked target rejected")
	}
	raw, err := readFile(v.bundle, "targets/"+name, limit)
	if err != nil {
		return nil, err
	}
	if info.VerifyLengthHashes(raw) != nil {
		return nil, errors.New("target digest or length rejected")
	}
	return raw, nil
}

func (v *verifier) targetJSON(name string) ([]byte, error) { return v.target(name, maxJSON) }

func (v *verifier) artifact(name, expected string) error {
	info := v.targets[name]
	if info == nil || info.Length < 1 || info.Length > 512*1024*1024 || len(info.Hashes) != 1 || hex.EncodeToString(info.Hashes["sha256"]) != expected || v.revoked[expected] {
		return errors.New("artifact target or revocation rejected")
	}
	f, err := openRegular(v.bundle, "targets/"+name)
	if err != nil {
		return errors.New("artifact unavailable")
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() != info.Length {
		return errors.New("artifact file rejected")
	}
	hash := sha256.New()
	length, err := io.Copy(hash, io.LimitReader(f, info.Length+1))
	if err != nil || length != info.Length || hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("artifact checksum rejected")
	}
	return nil
}

func (v *verifier) verifyRelease(source string) (ReleaseManifest, string, error) {
	var release ReleaseManifest
	raw, err := v.targetJSON("release.json")
	if err != nil {
		return release, "", err
	}
	if strictJSON(raw, &release) != nil || release.SchemaVersion != 1 || release.ArtifactClass != "foundation-candidate" || release.ProductionQualified || release.SourceSHA != source {
		return release, "", errors.New("release scope or source binding rejected")
	}
	files := []string{"runnerd-linux-amd64.tar.gz", "runnerd-linux-arm64.tar.gz", "sbom.spdx.json", "SHA256SUMS", "provenance.json"}
	if v.bootstrap.Profile == "github-candidate" {
		files = append(files, "provenance.sigstore.json", "sigstore-trusted-root.json")
	}
	if len(release.Files) != len(files) {
		return release, "", errors.New("unexpected or incomplete release files")
	}
	contents := map[string][]byte{}
	for _, name := range files {
		digest, ok := release.Files[name]
		if !ok || !digestPattern.MatchString(digest) {
			return release, "", errors.New("invalid release file digest")
		}
		if strings.HasSuffix(name, ".tar.gz") {
			if err = v.artifact(name, digest); err != nil {
				return release, "", err
			}
		} else {
			limit := int64(maxJSON)
			if name == "sbom.spdx.json" {
				limit = 32 * 1024 * 1024
			}
			contents[name], err = v.target(name, limit)
			if err != nil || sha(contents[name]) != digest {
				return release, "", errors.New("release file binding rejected")
			}
		}
	}
	// The checksum manifest has an exact set: both archives and their SBOM.
	var expected []string
	for _, name := range []string{"runnerd-linux-amd64.tar.gz", "runnerd-linux-arm64.tar.gz", "sbom.spdx.json"} {
		expected = append(expected, release.Files[name]+"  ./"+name)
	}
	sort.Strings(expected)
	lines := strings.Split(strings.TrimSuffix(string(contents["SHA256SUMS"]), "\n"), "\n")
	sort.Strings(lines)
	if strings.Join(lines, "\n") != strings.Join(expected, "\n") {
		return release, "", errors.New("checksum set rejected")
	}
	var sbom struct {
		SPDXVersion       string `json:"spdxVersion"`
		SPDXID            string `json:"SPDXID"`
		DataLicense       string `json:"dataLicense"`
		DocumentNamespace string `json:"documentNamespace"`
		Packages          []struct {
			Name   string `json:"name"`
			SPDXID string `json:"SPDXID"`
		} `json:"packages"`
	}
	if json.Unmarshal(contents["sbom.spdx.json"], &sbom) != nil || sbom.SPDXVersion != "SPDX-2.3" || sbom.SPDXID != "SPDXRef-DOCUMENT" || sbom.DataLicense != "CC0-1.0" || sbom.DocumentNamespace == "" || len(sbom.Packages) == 0 {
		return release, "", errors.New("SPDX document rejected")
	}
	if err = checkProvenance(contents["provenance.json"], release, v.bootstrap.Profile); err != nil {
		return release, "", err
	}
	if v.bootstrap.Profile == "github-candidate" {
		if err = v.githubProvenance(contents, release); err != nil {
			return release, "", err
		}
	}
	return release, sha(raw), nil
}

type provenance struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate struct {
		BuildDefinition struct {
			BuildType            string          `json:"buildType"`
			ExternalParameters   json.RawMessage `json:"externalParameters"`
			InternalParameters   json.RawMessage `json:"internalParameters"`
			ResolvedDependencies []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
		RunDetails json.RawMessage `json:"runDetails"`
	} `json:"predicate"`
}

func checkProvenance(raw []byte, release ReleaseManifest, profile string) error {
	var p provenance
	if strictJSON(raw, &p) != nil || p.Type != "https://in-toto.io/Statement/v1" || p.PredicateType != "https://slsa.dev/provenance/v1" {
		return errors.New("provenance statement rejected")
	}
	buildType := "https://actions.github.io/buildtypes/workflow/v1"
	if profile == "local-qualification" {
		buildType = repoURI + "/packaging/local-qualification/v1"
	}
	if p.Predicate.BuildDefinition.BuildType != buildType {
		return errors.New("provenance builder type rejected")
	}
	seen := map[string]bool{}
	for _, subject := range p.Subject {
		if seen[subject.Name] || (subject.Name != "SHA256SUMS" && subject.Name != "sbom.spdx.json" && subject.Name != "runnerd-linux-amd64.tar.gz" && subject.Name != "runnerd-linux-arm64.tar.gz") || len(subject.Digest) != 1 || subject.Digest["sha256"] != release.Files[subject.Name] {
			return errors.New("provenance subject set rejected")
		}
		seen[subject.Name] = true
	}
	if len(seen) != 4 {
		return errors.New("incomplete provenance subjects")
	}
	matched := false
	for _, dependency := range p.Predicate.BuildDefinition.ResolvedDependencies {
		if (dependency.URI == repoURI || dependency.URI == "git+"+repoURI+"@refs/heads/main") && dependency.Digest["gitCommit"] == release.SourceSHA {
			matched = true
		}
	}
	if !matched {
		return errors.New("provenance source commit rejected")
	}
	return nil
}

func (v *verifier) githubProvenance(files map[string][]byte, release ReleaseManifest) error {
	digest, _ := hex.DecodeString(release.Files["SHA256SUMS"])
	statement, err := githubStatement(v.bootstrap, files["sigstore-trusted-root.json"], files["provenance.sigstore.json"], "sha256", digest, release.SourceSHA, v.revokedKeys)
	if err != nil {
		return err
	}
	a, errA := protocol.CanonicalizeJSON(statement)
	b, errB := protocol.CanonicalizeJSON(files["provenance.json"])
	if errA != nil || errB != nil || !bytes.Equal(a, b) {
		return errors.New("provenance does not match signed statement")
	}
	return nil
}

// No online verifier option is enabled. Root material and transparency evidence
// must already be present, authenticated by the TUF target set.
func githubStatement(bootstrap Bootstrap, trustedRoot, signedJSON []byte, algorithm string, digest []byte, source string, revokedKeys map[string]bool) ([]byte, error) {
	if !digestPattern.MatchString(bootstrap.SigstoreRootSHA256) || sha(trustedRoot) != bootstrap.SigstoreRootSHA256 {
		return nil, errors.New("independent Sigstore root pin rejected")
	}
	material, err := root.NewTrustedRootFromJSON(trustedRoot)
	if err != nil {
		return nil, errors.New("provisioned Sigstore root rejected")
	}
	verifier, err := verify.NewVerifier(material, verify.WithSignedCertificateTimestamps(1), verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return nil, errors.New("offline signature verifier rejected")
	}
	var signed bundle.Bundle
	if err = signed.UnmarshalJSON(signedJSON); err != nil {
		return nil, errors.New("invalid Sigstore bundle")
	}
	identity, err := verify.NewShortCertificateIdentity(bootstrap.Issuer, "", bootstrap.Subject, "")
	if err != nil {
		return nil, errors.New("invalid provisioned signer identity")
	}
	verified, err := verifier.Verify(&signed, verify.NewPolicy(verify.WithArtifactDigest(algorithm, digest), verify.WithCertificateIdentity(identity)))
	if err != nil || verified.Signature == nil || verified.Signature.Certificate == nil || verified.Statement == nil {
		return nil, errors.New("offline Sigstore signature or identity rejected")
	}
	cert := verified.Signature.Certificate
	content, err := signed.VerificationContent()
	if err != nil || content.Certificate() == nil {
		return nil, errors.New("verified signing certificate missing")
	}
	key, err := x509.MarshalPKIXPublicKey(content.Certificate().PublicKey)
	if err != nil || revokedKeys[sha(key)] {
		return nil, errors.New("signing certificate key revoked")
	}
	if cert.SourceRepositoryURI != bootstrap.Repository || cert.SourceRepositoryIdentifier != bootstrap.RepositoryID || cert.SourceRepositoryOwnerIdentifier != bootstrap.OwnerID || cert.SourceRepositoryDigest != source || cert.BuildSignerDigest != source || cert.SourceRepositoryRef != bootstrap.SourceRef || cert.BuildSignerURI != bootstrap.Subject || cert.RunnerEnvironment != "github-hosted" {
		return nil, errors.New("authenticated build identity or revision rejected")
	}

	statement, err := protojson.Marshal(verified.Statement)
	if err != nil {
		return nil, errors.New("verified provenance unavailable")
	}
	return statement, nil
}
