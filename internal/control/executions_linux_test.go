//go:build linux

package control

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSensitiveExecutionDiagnosticsAndDurableDrainFailure(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	s, err := Listen(filepath.Join(dir, "control.sock"), func() Snapshot { return Snapshot{State: "drained"} }, func() {}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	reads := 0
	s.ExposeExecutions(func(context.Context, string, string) (any, error) {
		reads++
		return map[string]any{"executions": []any{}}, nil
	})
	r := httptest.NewRequest("GET", "/executions", nil).WithContext(context.WithValue(context.Background(), peerKey{}, uint32(65534)))
	w := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || reads != 0 {
		t.Fatal("observer read sensitive execution state")
	}
	r = r.WithContext(context.WithValue(context.Background(), peerKey{}, uint32(0)))
	w = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(w, r)
	if w.Code != 200 || reads != 1 {
		t.Fatal("owner diagnostics failed")
	}
	s.SetDurableDrain(func() error { return errors.New("synthetic persistence failure") })
	r = httptest.NewRequest("POST", "/drain", nil).WithContext(context.WithValue(context.Background(), peerKey{}, uint32(0)))
	w = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal("non-durable drain acknowledged")
	}
}
