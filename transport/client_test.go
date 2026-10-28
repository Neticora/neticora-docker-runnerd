package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

const timestamp = `"2026-10-25T00:00:00.000Z"`

func trustedClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := NewWithRoots(server.URL, time.Second, roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}
func TestHTTPSUsesExactSnapshot(t *testing.T) {
	message, err := protocol.EncodeValidatedJSON("Timestamp", []byte(timestamp))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body bytes.Buffer
		_, _ = body.ReadFrom(r.Body)
		if !bytes.Equal(body.Bytes(), message.Bytes()) || r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("request snapshot or headers changed")
		}
		_, _ = w.Write([]byte(timestamp))
	}))
	defer server.Close()
	client := trustedClient(t, server)
	raw, err := client.Post(context.Background(), "/heartbeat", "secret", message, "Timestamp")
	if err != nil || string(raw) != timestamp {
		t.Fatal(err)
	}
	if _, err := New("http://insecure.invalid", time.Second); err == nil {
		t.Fatal("HTTP accepted")
	}
	if _, err := New("https://secret@example.invalid", time.Second); err == nil {
		t.Fatal("credential URL accepted")
	}
	if _, err := NewWithRoots(server.URL, time.Second, []byte("invalid")); err == nil {
		t.Fatal("invalid root accepted")
	}
	untrusted, err := New(server.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.Close()
	if _, err = untrusted.Post(context.Background(), "/heartbeat", "secret", message, "Timestamp"); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}
func TestTransportRejectsUnsafeResponsesAndRedirects(t *testing.T) {
	message, err := protocol.EncodeValidatedJSON("Timestamp", []byte(timestamp))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Location", "/leak")
			w.WriteHeader(302)
		case "/compressed":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write([]byte(timestamp))
		case "/large":
			_, _ = w.Write([]byte(strings.Repeat("x", protocol.MaxWireBytes+1)))
		case "/secret":
			w.WriteHeader(401)
			_, _ = w.Write([]byte("do-not-log-this-token"))
		default:
			_, _ = w.Write([]byte(`{"unexpected":"secret"}`))
		}
	}))
	defer server.Close()
	client := trustedClient(t, server)
	for _, path := range []string{"/redirect", "/compressed", "/large", "/secret", "/invalid"} {
		before := calls.Load()
		_, err := client.Post(context.Background(), path, "secret", message, "Timestamp")
		if err == nil || strings.Contains(err.Error(), "do-not-log") || calls.Load() != before+1 {
			t.Fatal("response accepted, retried, followed, or disclosed")
		}
	}
	for _, path := range []string{"//other.invalid", "/../escape", "/path?token=secret", "/%2e%2e/escape"} {
		before := calls.Load()
		if _, err := client.Post(context.Background(), path, "secret", message, "Timestamp"); err == nil || calls.Load() != before {
			t.Fatal("unsafe path transmitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Post(ctx, "/heartbeat", "secret", message, "Timestamp"); err == nil {
		t.Fatal("cancelled operation continued")
	}
}

func TestHTTPSRejectsSchemaValidStaleMessageHashes(t *testing.T) {
	var fixtures []struct {
		ID, Schema       string
		Value            json.RawMessage
		Valid, HashValid bool
	}
	raw, err := os.ReadFile("../api/fixtures/outbound-wire.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	request, err := protocol.EncodeValidatedJSON("Timestamp", []byte(timestamp))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		t.Run(f.ID, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(f.Value) }))
			defer server.Close()
			client := trustedClient(t, server)
			response, err := client.Post(context.Background(), "/message", "secret", request, f.Schema)
			if (err == nil) != (f.Valid && f.HashValid) {
				t.Fatalf("response integrity acceptance mismatch: %v", err)
			}
			if err == nil && !bytes.Equal(response, f.Value) {
				t.Fatal("received source bytes changed")
			}
		})
	}
	// Recomputing the outer command digest must not conceal a stale nested spec.
	var command map[string]any
	if err = json.Unmarshal(fixtures[0].Value, &command); err != nil {
		t.Fatal(err)
	}
	command["spec"].(map[string]any)["poolId"] = "changed-pool"
	encoded, _ := json.Marshal(command)
	hash, err := protocol.PayloadHashJSON("HostCommand", encoded)
	if err != nil {
		t.Fatal(err)
	}
	command["payloadHash"] = hash
	encoded, _ = json.Marshal(command)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(encoded) }))
	defer server.Close()
	if _, err = trustedClient(t, server).Post(context.Background(), "/message", "secret", request, "HostCommand"); err == nil {
		t.Fatal("stale nested spec accepted from HTTPS response")
	}
}
