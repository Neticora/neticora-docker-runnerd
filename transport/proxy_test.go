package transport

import (
	"context"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

func TestProxyEnvironmentBoundary(t *testing.T) {
	// net/http caches its environment proxy function. A fresh process per case
	// exercises the public constructor without depending on test execution order.
	mode := os.Getenv("RUNNERD_PROXY_TEST_MODE")
	if mode == "" {
		for _, mode := range []string{"proxy", "bypass", "outage"} {
			t.Run(mode, func(t *testing.T) {
				command := exec.Command(os.Args[0], "-test.run=^TestProxyEnvironmentBoundary$", "-test.count=1")
				for _, entry := range os.Environ() {
					if !strings.HasPrefix(entry, "RUNNERD_PROXY_TEST_MODE=") {
						command.Env = append(command.Env, entry)
					}
				}
				command.Env = append(command.Env, "RUNNERD_PROXY_TEST_MODE="+mode)
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("proxy boundary failed: %v\n%s", err, output)
				}
			})
		}
		return
	}
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD"} {
		t.Setenv(name, "")
	}
	var requests, connects atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer host-canary" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("host/proxy credential separation failed")
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(timestamp))
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	target := "example.com:" + port
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connects.Add(1)
		if r.Method != http.MethodConnect || r.Host != target || r.Header.Get("Proxy-Authorization") != "Basic cHJveHk6Y2FuYXJ5" {
			t.Error("unexpected CONNECT target or proxy credential")
			http.Error(w, "rejected", http.StatusForbidden)
			return
		}
		if mode == "outage" {
			http.Error(w, "proxy-canary-must-not-escape", http.StatusBadGateway)
			return
		}
		upstream, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
		if err != nil {
			t.Error(err)
			return
		}
		defer upstream.Close()
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		_, _ = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { _, _ = io.Copy(upstream, connection); _ = upstream.Close() }()
		_, _ = io.Copy(connection, upstream)
	}))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", strings.Replace(proxy.URL, "http://", "http://proxy:canary@", 1))
	if mode == "bypass" {
		t.Setenv("NO_PROXY", "example.com")
	}
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := NewWithRoots("https://"+target, time.Second, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// Route the test hostname locally; TLS still verifies example.com's certificate.
	tr := client.http.Transport.(*http.Transport)
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == target {
			address = server.Listener.Addr().String()
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	}
	message, err := protocol.EncodeValidatedJSON("Timestamp", []byte(timestamp))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Post(context.Background(), "/heartbeat", "host-canary", message, "Timestamp")
	if mode == "outage" {
		if err == nil || connects.Load() != 1 || requests.Load() != 0 || strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), proxy.URL) {
			t.Fatal("proxy outage was retried, bypassed or disclosed")
		}
		return
	}
	expectedConnects := int64(1)
	if mode == "bypass" {
		expectedConnects = 0
	}
	if err != nil || requests.Load() != 1 || connects.Load() != expectedConnects {
		t.Fatalf("proxy/NO_PROXY boundary failed: %v", err)
	}
}
