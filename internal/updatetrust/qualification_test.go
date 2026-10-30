//go:build linux && runnerd_qualification

package updatetrust

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuiltCandidateQualification(t *testing.T) {
	input, output, source, verifier := os.Getenv("RUNNERD_QUALIFICATION_INPUT"), os.Getenv("RUNNERD_QUALIFICATION_OUTPUT"), os.Getenv("RUNNERD_QUALIFICATION_SOURCE"), os.Getenv("RUNNERD_QUALIFICATION_VERIFIER")
	if !filepath.IsAbs(input) || !filepath.IsAbs(output) || !filepath.IsAbs(verifier) || !commitPattern.MatchString(source) {
		t.Fatal("real candidate inputs, verifier and source snapshot required")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("qualification output must be new")
	}
	r := newTestRepository(t)
	for _, name := range []string{"runnerd-linux-amd64.tar.gz", "runnerd-linux-arm64.tar.gz", "sbom.spdx.json"} {
		raw, err := os.ReadFile(filepath.Join(input, name))
		if err != nil {
			t.Fatal(err)
		}
		r.files[name] = raw
	}
	// Assert this is a real binary/module SBOM, not only an empty SPDX envelope.
	var sbom struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"versionInfo"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(r.files["sbom.spdx.json"], &sbom); err != nil {
		t.Fatal(err)
	}
	for _, module := range []string{"github.com/Neticora/neticora-docker-runnerd", "github.com/theupdateframework/go-tuf/v2", "github.com/sigstore/sigstore-go"} {
		found := false
		for _, p := range sbom.Packages {
			if p.Name == module || strings.HasPrefix(p.Name, module+"/") {
				found = true
			}
		}
		if !found {
			t.Fatalf("built-binary SBOM missing %s", module)
		}
	}
	r.release.SourceSHA = source
	r.publish(1)
	if err := r.verify(); err != nil {
		t.Fatal(err)
	}
	// Retain only public test trust, signed metadata and verified artifacts.
	// Private signing keys never leave this test process or authorize a release.
	if err := os.Mkdir(output, 0700); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(r.dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(r.dir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(output, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the shipped Linux command against the real built archives.
	if wait := time.Until(r.now.Add(10 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	common := []string{"--qualification-only", "--bootstrap", filepath.Join(output, "bootstrap.json"), "--bootstrap-sha256", r.pin, "--state", filepath.Join(output, "cli-state")}
	command := exec.Command(verifier, append(common, "--initialize-state")...)
	if logs, err := command.CombinedOutput(); err != nil {
		t.Fatalf("verifier initialization failed: %v %s", err, logs)
	}
	command = exec.Command(verifier, append(common, "--bundle", filepath.Join(output, "bundle"), "--source", source)...)
	logs, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("shipped verifier failed: %v %s", err, logs)
	}
	var result Result
	if json.Unmarshal(logs, &result) != nil || result.ProductionQualified || result.VerificationProfile != "local-qualification" || result.SourceSHA != source {
		t.Fatal("invalid shipped verifier result")
	}
	testWrite(t, filepath.Join(output, "qualification.json"), testJSON(t, map[string]any{"result": result, "bootstrapSha256": r.pin, "sbomPackageCount": len(sbom.Packages), "sourceSnapshot": source, "githubCandidateSigningPerformed": false, "privateKeysRetained": false}))
	t.Log("PASS: actual amd64/arm64 archives, real SPDX SBOM, checksums, signed provenance/metadata and shipped offline verifier; qualification-only trust")
}
