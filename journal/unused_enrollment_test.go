package journal

import (
	"context"
	"testing"
)

func TestUnusedEnrollmentRejectsAllHistory(t *testing.T) {
	ctx := context.Background()
	s := recovery(t, privateDir(t), Options{})
	if e := s.UnusedEnrollment(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.ExecContext(ctx, `UPDATE metadata SET inventory_generation='1' WHERE singleton=1`); e != nil {
		t.Fatal(e)
	}
	// Integrity or explicit history checks must refuse; no cleanup state authorizes reuse.
	if e := s.UnusedEnrollment(ctx); e == nil {
		t.Fatal("bound native state treated as unused")
	}
}
