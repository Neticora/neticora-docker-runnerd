//go:build linux

package service

import (
	"context"
	"encoding/json"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/control"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalServiceCancellationAndRestart(t *testing.T) {
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "control.sock")
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Run(ctx, config.Config{StateDir: state}, socket) }()
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
		}}
		client := &http.Client{Transport: transport, Timeout: time.Second}
		deadline := time.Now().Add(3 * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			response, err := client.Get("http://local/status")
			if err == nil {
				var s control.Snapshot
				err = json.NewDecoder(response.Body).Decode(&s)
				response.Body.Close()
				if err != nil || s.AdmissionEnabled || s.RuntimeQualified || s.State != "drained" {
					t.Fatal("unqualified execution advertised")
				}
				ready = true
				break
			}
			select {
			case err := <-done:
				cancel()
				t.Fatalf("startup failed: %v", err)
			default:
				time.Sleep(10 * time.Millisecond)
			}
		}
		cancel()
		transport.CloseIdleConnections()
		if !ready {
			t.Fatal("service never became responsive")
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("shutdown hung")
		}
		if _, err := os.Lstat(socket); !os.IsNotExist(err) {
			t.Fatal("socket was not removed after graceful shutdown")
		}
		if _, err := os.Stat(filepath.Join(state, "instance.lock")); err != nil {
			t.Fatal("installation lock inode must survive shutdown")
		}

	}
}
