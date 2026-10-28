//go:build linux

package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadOnlyCommandsAndAdministrativeAuthorization(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.sock")
	changes, audits := 0, 0
	server, err := Listen(path, func() Snapshot { return Snapshot{State: "drained"} }, func() { changes++ }, func(string) { audits++ })
	if err != nil {
		t.Fatal(err)
	}
	defer server.listener.Close()
	for _, route := range []string{"status", "doctor", "capabilities"} {
		response := httptest.NewRecorder()
		server.http.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/"+route, nil))
		if response.Code != 200 || changes != 0 || audits != 0 {
			t.Fatal("read-only command mutated state")
		}
	}
	for _, uid := range []int{-1, 65534} {
		req := httptest.NewRequest(http.MethodPost, "/drain", nil)
		if uid >= 0 && uid != os.Geteuid() {
			req = req.WithContext(context.WithValue(req.Context(), peerKey{}, uint32(uid)))
		}
		response := httptest.NewRecorder()
		server.http.Handler.ServeHTTP(response, req)
		if response.Code != 403 || changes != 0 {
			t.Fatal("unauthorized mutation accepted")
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/drain", nil).WithContext(context.WithValue(context.Background(), peerKey{}, uint32(os.Geteuid())))
	response := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(response, req)
	if response.Code != 200 || changes != 1 || audits != 1 {
		t.Fatal("authorized mutation was not audited")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}
func TestControlNeverReplacesExistingPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.sock")
	if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if server, err := Listen(path, func() Snapshot { return Snapshot{} }, func() {}, func(string) {}); err == nil {
		server.listener.Close()
		t.Fatal("replaced existing path")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "preserve" {
		t.Fatal("existing path changed")
	}
}
