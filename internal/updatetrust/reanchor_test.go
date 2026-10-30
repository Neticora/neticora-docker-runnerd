//go:build linux

package updatetrust

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestExplicitBootstrapRenewalPreservesRevocationAndRollback(t *testing.T) {
	r := newTestRepository(t)
	revoked := strings.Repeat("f", 64)
	r.rev.SHA256 = []string{revoked}
	r.publish(2)
	if err := r.verify(); err != nil {
		t.Fatal(err)
	}
	if wait := time.Until(r.now); wait > 0 {
		time.Sleep(wait)
	}
	next := r.b
	next.ExpiresAt = next.ExpiresAt.Add(time.Hour)
	raw := testJSON(t, next)
	path := filepath.Join(r.dir, "next-bootstrap.json")
	testWrite(t, path, raw)
	if err := Reanchor(r.bootstrap, r.pin, path, sha(raw), r.state, true); err != nil {
		t.Fatal(err)
	}
	c, err := loadCheckpoint(r.state, sha(raw))
	if err != nil || !c.RevokedFiles[revoked] || c.ReleaseSequence != "1" || c.Versions[metadata.TARGETS] != 2 {
		t.Fatal("renewal reset trust history")
	}
	r.bootstrap, r.pin = path, sha(raw)
	r.now = time.Now().UTC().Add(time.Millisecond)
	if err = r.verify(); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapRenewalRejectsSelfAuthorizedRootAndChangedIdentity(t *testing.T) {
	for _, kind := range []string{"root", "identity"} {
		t.Run(kind, func(t *testing.T) {
			r := newTestRepository(t)
			if err := r.verify(); err != nil {
				t.Fatal(err)
			}
			if wait := time.Until(r.now); wait > 0 {
				time.Sleep(wait)
			}
			next := r.b
			if kind == "identity" {
				next.RootID = "different-authority"
			} else {
				root, _ := newTestRoot(t, r.now, 2)
				raw, err := root.ToBytes(false)
				if err != nil {
					t.Fatal(err)
				}
				next.Root = raw
				next.RootSHA256 = sha(raw)
				next.RootVersion = 2
			}
			raw := testJSON(t, next)
			path := filepath.Join(r.dir, "next-bootstrap.json")
			testWrite(t, path, raw)
			if err := Reanchor(r.bootstrap, r.pin, path, sha(raw), r.state, true); err == nil {
				t.Fatal("invalid independent renewal accepted")
			}
			if _, err := loadCheckpoint(r.state, r.pin); err != nil {
				t.Fatal("failed renewal changed original pin")
			}
		})
	}
}
