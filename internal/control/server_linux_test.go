//go:build linux

package control

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadOnlyCommandsAndAdministrativeAuthorization(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.sock")
	changes := 0
	var audits []string
	server, err := Listen(path, func() Snapshot { return Snapshot{State: "drained"} }, func() { changes++ }, func(event string) { audits = append(audits, event) })
	if err != nil {
		t.Fatal(err)
	}
	defer server.listener.Close()
	for _, route := range []string{"status", "doctor", "capabilities"} {
		response := httptest.NewRecorder()
		server.http.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/"+route, nil))
		if response.Code != 200 || changes != 0 || len(audits) != 0 {
			t.Fatal("read-only command mutated state")
		}
	}
	for index, uid := range []int{-1, 65534} {
		req := httptest.NewRequest(http.MethodPost, "/drain", nil)
		if uid >= 0 && uid != os.Geteuid() {
			req = req.WithContext(context.WithValue(req.Context(), peerKey{}, uint32(uid)))
		}
		response := httptest.NewRecorder()
		server.http.Handler.ServeHTTP(response, req)
		if response.Code != 403 || changes != 0 || len(audits) != index+1 || audits[index] != "drain rejected" {
			t.Fatal("unauthorized mutation accepted")
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/drain", nil).WithContext(context.WithValue(context.Background(), peerKey{}, uint32(os.Geteuid())))
	response := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(response, req)
	if response.Code != 200 || changes != 1 || len(audits) != 3 || audits[2] != "drain accepted" {
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

func TestDiagnosticsAndUnsupportedOperationsDoNotExposeOrMutate(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	mutations := 0
	var audits []string
	server, err := Listen(filepath.Join(dir, "control.sock"), func() Snapshot {
		return Snapshot{State: "drained", AdmissionEnabled: false, RuntimeQualified: false}
	}, func() { mutations++ }, func(event string) { audits = append(audits, event) })
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, operation := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/status", 200}, {"GET", "/doctor", 200}, {"GET", "/capabilities", 200},
		{"POST", "/drain", 403}, {"GET", "/drain", 405},
		{"POST", "/recover", 404}, {"POST", "/enroll", 404},
		{"GET", "/executions", 404}, {"GET", "/support-bundle", 404},
	} {
		t.Run(operation.method+operation.path, func(t *testing.T) {
			req := httptest.NewRequest(operation.method, operation.path+"?token=canary-secret", strings.NewReader("canary-secret"))
			req.Header.Set("Authorization", "Bearer canary-secret")
			response := httptest.NewRecorder()
			server.http.Handler.ServeHTTP(response, req)
			body, err := io.ReadAll(response.Result().Body)
			if err != nil || response.Code != operation.status || mutations != 0 || strings.Contains(string(body), "canary-secret") {
				t.Fatal("unsafe diagnostic or administrative operation")
			}
		})
	}
	if len(audits) != 1 || audits[0] != "drain rejected" {
		t.Fatal("administrative rejection must emit only the redacted audit event")
	}
}
