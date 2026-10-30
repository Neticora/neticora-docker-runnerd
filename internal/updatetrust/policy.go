// Package updatetrust verifies offline foundation-update bundles. It never
// downloads roots, installs artifacts, enables admission or changes networking.
package updatetrust

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

const maxJSON = 1_000_000

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var commitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

// Bootstrap is provisioned independently of the downloaded release. Its complete
// bytes are pinned through an independent installer/operator channel. No private
// signing keys belong in this file or on an agent host.
type Bootstrap struct {
	SchemaVersion        int             `json:"schemaVersion"`
	RootID               string          `json:"rootId"`
	RootVersion          int64           `json:"rootVersion"`
	RootSHA256           string          `json:"rootSha256"`
	Root                 json.RawMessage `json:"root"`
	SigstoreRootSHA256   string          `json:"sigstoreRootSha256"`
	ValidFrom            time.Time       `json:"validFrom"`
	ExpiresAt            time.Time       `json:"expiresAt"`
	MaxOfflineAgeSeconds int64           `json:"maxOfflineAgeSeconds"`
	Profile              string          `json:"profile"`
	Repository           string          `json:"repository"`
	SourceRef            string          `json:"sourceRef"`
	RepositoryID         string          `json:"repositoryId"`
	OwnerID              string          `json:"ownerId"`
	Issuer               string          `json:"issuer"`
	Subject              string          `json:"subject"`
}

func strictJSON(data []byte, into any) error {
	if len(data) == 0 || len(data) > maxJSON {
		return errors.New("invalid bounded JSON")
	}
	if _, err := protocol.CanonicalizeJSON(data); err != nil {
		return errors.New("invalid strict JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return errors.New("invalid JSON fields")
	}
	return nil
}

func sha(data []byte) string { value := sha256.Sum256(data); return hex.EncodeToString(value[:]) }

func loadBootstrap(path, pin string, now time.Time) (Bootstrap, error) {
	var b Bootstrap
	data, err := hostfs.ReadPrivate(path, maxJSON)
	if err != nil || !digestPattern.MatchString(pin) || sha(data) != pin {
		return b, errors.New("independent bootstrap pin or protected file rejected")
	}
	if err = strictJSON(data, &b); err != nil {
		return b, err
	}
	if b.SchemaVersion != 1 || !namePattern.MatchString(b.RootID) || b.RootVersion < 1 ||
		sha(b.Root) != b.RootSHA256 || b.ValidFrom.IsZero() || b.ValidFrom.After(now) || !b.ExpiresAt.After(now) ||
		!b.ExpiresAt.After(b.ValidFrom) || b.MaxOfflineAgeSeconds < 1 || b.MaxOfflineAgeSeconds > 7*24*60*60 {
		return b, errors.New("bootstrap validity or offline bound rejected")
	}
	if b.Profile != "github-candidate" && b.Profile != "local-qualification" {
		return b, errors.New("unsupported trust profile")
	}
	if b.Repository != "https://github.com/Neticora/neticora-docker-runnerd" || b.SourceRef != "refs/heads/main" ||
		b.Issuer != "https://token.actions.githubusercontent.com" ||
		b.Subject != b.Repository+"/.github/workflows/release-candidate.yml@refs/heads/main" {
		return b, errors.New("publisher identity rejected")
	}
	if b.Profile == "github-candidate" && (b.RepositoryID == "" || b.OwnerID == "") {
		return b, errors.New("immutable repository ownership identifiers required")
	}
	if b.Profile == "github-candidate" && !digestPattern.MatchString(b.SigstoreRootSHA256) {
		return b, errors.New("independent Sigstore root pin required")
	}
	trusted, err := trustedmetadata.New(b.Root)
	if err != nil || trusted.Root.Signed.Version != b.RootVersion {
		return b, errors.New("bootstrap root signature or version rejected")
	}
	if err = checkRoles(trusted, b.Profile); err != nil {
		return b, err
	}
	return b, nil
}

func checkRoles(t *trustedmetadata.TrustedMetadata, profile string) error {
	for _, name := range []string{"root", "timestamp", "snapshot", "targets"} {
		role := t.Root.Signed.Roles[name]
		if role == nil || role.Threshold < 1 || role.Threshold > len(role.KeyIDs) {
			return errors.New("invalid trust role threshold")
		}
		if name == "root" && profile == "github-candidate" && role.Threshold < 2 {
			return errors.New("GitHub trust root requires an offline threshold")
		}
		seen := map[string]bool{}
		for _, id := range role.KeyIDs {
			if seen[id] || t.Root.Signed.Keys[id] == nil {
				return errors.New("invalid trust role keys")
			}
			seen[id] = true
		}
	}
	return nil
}

// readFile holds the opened file through hashing. A release directory is
// untrusted; confined roots and regular-file checks prevent special-file hangs
// and escape. JSON reads are separately bounded.
func readFile(root *os.Root, path string, limit int64) ([]byte, error) {
	f, err := openRegular(root, path)
	if err != nil {
		return nil, errors.New("bundle file unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("bundle file type or size rejected")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("bundle file unreadable or oversized")
	}
	return data, nil
}
