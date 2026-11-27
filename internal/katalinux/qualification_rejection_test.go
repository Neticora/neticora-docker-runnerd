package katalinux

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProductionLoaderRejectsLabEnvelope(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	file := filepath.Join(dir, "lab.json")
	if err := os.WriteFile(file, []byte(`{"version":"runnerd09-lab-authority-v1","manifest":{"qualified":false},"binding":{},"signature":"test"}`), 0600); err != nil {
		t.Fatal(err)
	}
	p := profile(blockFixture())
	if _, err := Load(file, filepath.Join(dir, "missing-key"), p.EvidenceDirectory, p.JournalDirectory, p.Base); err == nil {
		t.Fatal("lab envelope passed production loader")
	}
}
