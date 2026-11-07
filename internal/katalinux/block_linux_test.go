//go:build linux

package katalinux

import (
	"encoding/json"
	"os"
	"syscall"
	"testing"
)

func TestBlockReleaseIntentPreservesAmbiguity(t *testing.T) {
	r := BlockRecord{Phase: "ready", Bytes: 4096, FileDevice: 7, FileInode: 9}
	if _, err := releaseIntent(r, nil, true); err == nil {
		t.Fatal("unexpected missing backing became release intent")
	}
	if r.Phase != "ready" {
		t.Fatal("failed read changed durable state")
	}
	r.Phase = "releasing"
	if next, err := releaseIntent(r, nil, true); err != nil || next.Phase != "releasing" {
		t.Fatal("post-unlink crash cannot resume")
	}
	r.Phase = "claiming"
	r.FileInode = 0
	st := syscall.Stat_t{Dev: 7, Ino: 11, Size: 0}
	next, err := releaseIntent(r, &st, false)
	if err != nil || next.FileInode != 11 {
		t.Fatal("owned create-before-inode-record crash cannot clean")
	}
	next.FileInode = 12
	if _, err = releaseIntent(next, &st, false); err == nil {
		t.Fatal("unrelated replacement file accepted")
	}
	r.Phase = "unknown"
	if _, err = releaseIntent(r, nil, true); err == nil {
		t.Fatal("unknown phase invents release authority")
	}
}
func TestBlockDurableOwnershipSurvivesReopenAndRejectsCorruption(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	r := BlockRecord{Version: "runnerd09-block-allocation-v1", Name: "owned", Phase: "allocated", Bytes: 4096, FileInode: 9}
	if err = writeBlockState(root, blockSlot, r); err != nil {
		t.Fatal(err)
	}
	got, err := readBlockState(root, blockSlot)
	if err != nil || got.FileInode != 9 || got.Phase != "allocated" {
		t.Fatal("ownership lost after reopen", err)
	}
	raw, _ := root.ReadFile(blockSlot)
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		t.Fatal("decode")
	}
	body["record"].(map[string]any)["fileInode"] = float64(10)
	raw, _ = json.Marshal(body)
	if err = root.WriteFile(blockSlot, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readBlockState(root, blockSlot); err == nil {
		t.Fatal("corrupt inode ownership accepted")
	}
}
func TestBlockTombstoneKeepsOriginalAllocationIdentity(t *testing.T) {
	r := BlockRecord{Version: "runnerd09-block-allocation-v1", Profile: "profile", Name: "attempt", UUID: "uuid", Bytes: 4096, FileDevice: 7, FileInode: 9, LoopDevice: 11, Phase: "ready"}
	final := r
	final.Phase = "released"
	if !sameAllocation(r, final) {
		t.Fatal("release lost physical identity")
	}
	final.FileInode++
	if sameAllocation(r, final) {
		t.Fatal("tombstone can release another backing file")
	}
}
