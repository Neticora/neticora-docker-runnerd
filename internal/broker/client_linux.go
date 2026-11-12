//go:build linux

package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"time"
)

// Call authenticates the actual connected broker peer; it never reads Docker
// environment variables, redirects requests, or accepts runtime descriptors.
func Call(ctx context.Context, socket string, request Request) (Response, error) {
	var result Response
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
		return result, ErrRejected
	}
	timeout := 10 * time.Second
	if request.Operation == "ExecuteOperation" {
		timeout = 6 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body, err := json.Marshal(request)
	if err != nil || len(body) > MaxMessage {
		return result, ErrRejected
	}
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
		if err != nil {
			return nil, err
		}
		uid, err := peerUID(conn)
		if err != nil || uid != 0 {
			conn.Close()
			return nil, ErrRejected
		}
		return conn, nil
	}}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://broker/v1/request", bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRejected }}).Do(req)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxMessage+1))
	if err != nil || decode(raw, &result) != nil || result.Version != Version {
		return Response{}, ErrRejected
	}
	if response.StatusCode != http.StatusOK {
		return result, ErrRejected
	}
	return result, nil
}
