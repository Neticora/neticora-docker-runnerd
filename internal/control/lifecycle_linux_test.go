//go:build linux

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

func localTestClient(t *testing.T, path string) *http.Client {
	t.Helper()
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func TestActiveRequestShutdownAndImmediateRebind(t *testing.T) {
	path := privateSocketPath(t)
	original, err := Listen(path, func() Snapshot { return Snapshot{} }, func() {}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	original.http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
			_, _ = io.WriteString(w, "original response")
		case <-r.Context().Done():
		}
	})
	t.Cleanup(func() { unblock(); _ = original.Close() })
	served := make(chan error, 1)
	go func() { served <- original.Serve() }()
	oldClient := localTestClient(t, path)
	oldResponse := make(chan error, 1)
	go func() {
		response, err := oldClient.Get("http://local/status")
		if err == nil {
			defer response.Body.Close()
			var data []byte
			data, err = io.ReadAll(response.Body)
			if err == nil && (response.StatusCode != http.StatusOK || string(data) != "original response") {
				err = errors.New("active original request changed during shutdown")
			}
		}
		oldResponse <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request never entered the original handler")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- original.Shutdown(ctx) }()
	// Serve returns when the accepting listener closes, while Shutdown must still
	// wait for the blocked request. Rebind before releasing that old request.
	select {
	case err = <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("listener did not stop accepting")
	}
	replacement, err := Listen(path, func() Snapshot { return Snapshot{} }, func() {}, func(string) {})
	if err != nil {
		t.Fatalf("immediate rebind failed: %v", err)
	}
	replacement.http.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "replacement response") })
	replacementServed := make(chan error, 1)
	go func() { replacementServed <- replacement.Serve() }()
	t.Cleanup(func() {
		_ = replacement.Close()
		select {
		case <-replacementServed:
		case <-time.After(5 * time.Second):
			t.Error("replacement server did not exit")
		}
	})
	replacementIdentity, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	newClient := localTestClient(t, path)
	assertReplacement := func() {
		t.Helper()
		response, err := newClient.Get("http://local/status")
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || string(data) != "replacement response" {
			t.Fatal("replacement did not serve its own response")
		}
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(replacementIdentity, current) {
			t.Fatal("original cleanup removed or replaced the new socket")
		}
	}
	assertReplacement()
	select {
	case err = <-stopped:
		t.Fatalf("shutdown completed with an active request: %v", err)
	default:
	}
	// Concurrent, repeated closes of the original listener must never touch the
	// replacement socket or interrupt the original established connection.
	var closes sync.WaitGroup
	closeErrors := make(chan error, 8)
	for i := 0; i < 8; i++ {
		closes.Add(1)
		go func() { defer closes.Done(); closeErrors <- original.listener.Close() }()
	}
	closes.Wait()
	close(closeErrors)
	for err = range closeErrors {
		if err != nil {
			t.Fatal(err)
		}
	}
	assertReplacement()
	unblock()
	select {
	case err = <-oldResponse:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("original request did not complete")
	}
	select {
	case err = <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("shutdown did not complete after request drained")
	}
	if err = original.Close(); err != nil {
		t.Fatal(err)
	}
	assertReplacement()
}
