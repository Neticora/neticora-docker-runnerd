//go:build linux

package execution

import (
	"context"
	"testing"
)

func TestResumePreservesUnfinishedExecutionAndRuntimeOwnership(t *testing.T) {
	c, runtime, _, original := setup(t)
	if err := c.CheckResume(context.Background()); err == nil {
		t.Fatal("resumed unfinished original execution")
	}
	got := current(t, c)
	if got.Identity != original.Identity || got.State != original.State || runtime.creates != 0 || runtime.starts != 0 || runtime.removes != 0 {
		t.Fatal("resume changed ownership or physical resources")
	}
	c.recoveryOnly = true
	if err := c.CheckResume(context.Background()); err == nil {
		t.Fatal("terminal recovery mode resumed admission")
	}
}
