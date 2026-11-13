//go:build linux && runnerd_broker_qualification

package broker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQualificationMissingFaultSelectorDoesNotConsumeOrFail(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "fault.json")
	q := ExecutionGrantRequest{Operation: "PrepareImage", ExecutionID: "exact-original"}
	if err := qualificationCheckpoint(file)("before-effect", q); err != nil {
		t.Fatal("unconfigured fault held committed work", err)
	}
	if _, err := os.Lstat(file + ".consumed"); !os.IsNotExist(err) {
		t.Fatal("missing selector became fault evidence", err)
	}
	if err := os.WriteFile(file, []byte(`{"operation":"RemoveExecution","point":"after-effect","executionId":"different"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := qualificationCheckpoint(file)("before-effect", q); err != nil {
		t.Fatal("unmatched selector changed work", err)
	}
}
