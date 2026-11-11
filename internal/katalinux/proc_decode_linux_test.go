//go:build linux

package katalinux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProcDecoderUsesFreshBytesAndCurrentTarget(t *testing.T) {
	task := t.TempDir()
	file := filepath.Join(task, "maps")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(file, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.WithValue(t.Context(), procDecodeKey{}, &procDecoder{})
	r := BlockRecord{FileDevice: unix.Mkdev(8, 1), FileInode: 33}
	write("1000-2000 rw-s 0000 08:01 22 /not-target\n")
	if err := noMappedBlockUsers(ctx, task, r); err != nil {
		t.Fatal(err)
	}
	// Reusing the SAME fresh bytes cannot reuse a negative for another inode.
	other := r
	other.FileInode = 22
	if err := noMappedBlockUsers(ctx, task, other); !errors.Is(err, ErrQualification) {
		t.Fatal("target-dependent decision cached", err)
	}
	// A stable task path/ID and equal input length do not establish unchanged maps.
	write("1000-2000 rw-s 0000 08:01 33 /now-target\n")
	if err := noMappedBlockUsers(ctx, task, r); !errors.Is(err, ErrQualification) {
		t.Fatal("changed mapping missed", err)
	}
	write("1000-2000 rw-s 0000 invalid 33 /unknown\n")
	if err := noMappedBlockUsers(ctx, task, r); !errors.Is(err, ErrQualification) {
		t.Fatal("malformed fresh mapping accepted", err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := noMappedBlockUsers(ctx, task, r); !errors.Is(err, ErrQualification) {
		t.Fatal("unreadable observable task accepted", err)
	}
}

func TestProcDecoderBudgetAndLargeMapsDoNotSkipChecks(t *testing.T) {
	d := &procDecoder{bytes: procDecodeBudget, entries: 128}
	ctx := context.WithValue(t.Context(), procDecodeKey{}, d)
	task := t.TempDir()
	line := "1000-2000 r--p 0000 08:01 22 /padding\n"
	raw := strings.Repeat(line, 1+(1<<20)/len(line)) + "2000-3000 rw-s 0000 08:01 33 /held\n"
	if err := os.WriteFile(filepath.Join(task, "maps"), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := noMappedBlockUsers(ctx, task, BlockRecord{FileDevice: unix.Mkdev(8, 1), FileInode: 33}); !errors.Is(err, ErrQualification) {
		t.Fatal("large fresh maps bypassed held inode", err)
	}
	if len(d.maps) != 0 {
		t.Fatal("cache budget exceeded")
	}
}

func TestProcMountDecoderExactContentAndCancellation(t *testing.T) {
	d := &procDecoder{}
	ctx := context.WithValue(t.Context(), procDecodeKey{}, d)
	raw := []byte("1 0 8:1 / /root rw - ext4 /dev/x rw\n")
	first, err := decodedMounts(ctx, raw)
	if err != nil || len(first) != 1 {
		t.Fatal(err)
	}
	copy(raw, []byte("1 0 8:1 / /else rw - ext4 /dev/x rw\n"))
	second, err := decodedMounts(ctx, raw)
	if err != nil || second[0].Point != "/else" || first[0].Point != "/root" {
		t.Fatal("fresh body or cached input alias changed", err)
	}
	if _, err := decodedMounts(ctx, []byte("1 0 broken / /else rw\n")); !errors.Is(err, ErrQualification) {
		t.Fatal("unknown fresh mount state accepted", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := decodedMounts(canceled, raw); !errors.Is(err, context.Canceled) {
		t.Fatal("memo lookup ignored cancellation", err)
	}
	if _, err := decodedMaps(canceled, []byte("")); !errors.Is(err, context.Canceled) {
		t.Fatal("maps lookup ignored cancellation", err)
	}
}
