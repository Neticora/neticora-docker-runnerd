//go:build linux

package control

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestResumeRequiresOwnerAndIndependentServiceChecks(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := Listen(filepath.Join(dir, "control.sock"), func() Snapshot { return Snapshot{} }, func() {}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	allowed, calls := false, 0
	s.ExposeResume(func(context.Context) error {
		calls++
		if !allowed {
			return errors.New("recovery required")
		}
		return nil
	}, func(string) {})
	for _, tc := range []struct {
		uid    int
		permit bool
		status int
	}{{-1, false, 403}, {65534, false, 403}, {os.Geteuid(), false, 503}, {os.Geteuid(), true, 200}} {
		allowed = tc.permit
		req := httptest.NewRequest("POST", "/resume", nil)
		if tc.uid >= 0 {
			req = req.WithContext(context.WithValue(req.Context(), peerKey{}, uint32(tc.uid)))
		}
		w := httptest.NewRecorder()
		s.http.Handler.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Fatal(w.Code, tc.status)
		}
	}
	if calls != 2 {
		t.Fatal("unauthorized resume called service", calls)
	}
}
