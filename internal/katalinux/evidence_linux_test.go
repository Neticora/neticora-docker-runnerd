//go:build linux

package katalinux

import (
	"encoding/json"
	"os"
	"testing"
)

func TestPhysicalEvidenceCorruptionIsNotAbsence(t *testing.T) {
	// Codec/durability test only. Production permission gates are exercised by
	// hostfs tests; an ordinary confined root keeps this test portable in UID-
	// mapped developer environments without relaxing any production check.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	record := Evidence{Version: "runnerd09-physical-v1", Profile: "profile", Container: "owned", SpecHash: "spec", Generation: "1", Prepared: true}
	if err = persist(root, "record.json", record); err != nil {
		t.Fatal(err)
	}
	raw, err := root.ReadFile("record.json")
	if err != nil {
		t.Fatal(err)
	}
	var got Evidence
	if readEvidence(raw, &got) != nil {
		t.Fatal("durable record rejected")
	}
	var edited map[string]any
	if json.Unmarshal(raw, &edited) != nil {
		t.Fatal("decode")
	}
	edited["record"].(map[string]any)["container"] = "unrelated"
	raw, _ = json.Marshal(edited)
	if readEvidence(raw, &got) == nil {
		t.Fatal("corrupt ownership metadata accepted")
	}
}
func TestHostObserverCannotRunAsAnUnprivilegedCaller(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires ordinary caller")
	}
	if ServeObserver(t.Context(), "/nonexistent/config") == nil {
		t.Fatal("privilege boundary bypassed")
	}
}
