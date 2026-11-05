// Package transport provides a bounded HTTPS transport. Credentials are supplied
// separately per call and never returned in diagnostics. It does not authenticate
// wire claims or make durable execution decisions.
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

type Client struct {
	base  *url.URL
	http  *http.Client
	clock atomic.Pointer[clockSample]
}

type clockSample struct {
	observed time.Time
	skew     time.Duration
}

func (c *Client) observeClock(response *http.Response) {
	server, err := http.ParseTime(response.Header.Get("Date"))
	if err != nil {
		c.clock.Store(nil)
		return
	}
	now := time.Now()
	c.clock.Store(&clockSample{observed: now, skew: server.Sub(now)})
}
func (c *Client) ClockSkew() (time.Duration, bool) {
	s := c.clock.Load()
	if s == nil || time.Since(s.observed) > time.Minute {
		return 0, false
	}
	return s.skew, true
}

func New(endpoint string, timeout time.Duration) (*Client, error) {
	return NewWithRoots(endpoint, timeout, nil)
}

// NewWithRoots adds explicitly provisioned PEM roots to system roots. It never
// disables hostname, certificate validity or chain verification.
func NewWithRoots(endpoint string, timeout time.Duration, rootPEM []byte) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("invalid HTTPS transport configuration")
	}
	var roots *x509.CertPool
	if len(rootPEM) > 0 {
		roots, _ = x509.SystemCertPool()
		if roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(rootPEM) {
			return nil, errors.New("invalid provisioned CA bundle")
		}
	}
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, IdleConnTimeout: time.Minute, MaxConnsPerHost: 4, MaxIdleConns: 4, MaxResponseHeaderBytes: 16384, DisableCompression: true}
	return &Client{base: u, http: &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }

// Post sends precisely the validated snapshot. responseSchema is required;
// responses require both wire validity and defined logical-hash agreement.
// Accepted responses are not authenticated command authority. No automatic retry,
// redirect following or compression can duplicate or transform a request.
func (c *Client) Post(ctx context.Context, path, token string, message protocol.Outbound, responseSchema string) ([]byte, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#\\\r\n") || strings.Contains(path, "..") || strings.Contains(path, "%") || responseSchema == "" {
		return nil, errors.New("invalid protocol request path or response schema")
	}
	data := message.Bytes()
	if len(data) == 0 {
		return nil, errors.New("empty outbound message")
	}
	if strings.ContainsAny(token, "\r\n") || (token == "" && path != "/enroll" && path != "/token") {
		return nil, errors.New("invalid host credential")
	}
	endpoint := *c.base
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	endpoint.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("cannot create protocol request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("protocol request failed")
	}
	defer response.Body.Close()
	c.observeClock(response)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New("protocol request rejected")
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return nil, errors.New("compressed protocol response is disabled")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxWireBytes+1))
	if err != nil || len(raw) > protocol.MaxWireBytes {
		return nil, errors.New("protocol response unreadable or oversized")
	}
	if err := protocol.ValidateInboundJSON(responseSchema, raw); err != nil {
		return nil, errors.New("invalid protocol response")
	}
	return raw, nil
}

// Config fetches a fresh, validated narrowing proposal. Callers must intersect it
// with root-owned local policy; a server response never grants local authority.
func (c *Client) Config(ctx context.Context, token string) ([]byte, error) {
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("invalid host credential")
	}
	endpoint := *c.base
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/me/config"
	endpoint.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, errors.New("cannot create protocol request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	response, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("protocol request failed")
	}
	defer response.Body.Close()
	c.observeClock(response)
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("protocol request rejected")
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return nil, errors.New("compressed protocol response is disabled")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxWireBytes+1))
	if err != nil || len(raw) > protocol.MaxWireBytes {
		return nil, errors.New("protocol response unreadable or oversized")
	}
	if err = protocol.ValidateInboundJSON("ConfigResponse", raw); err != nil {
		return nil, errors.New("invalid protocol response")
	}
	return raw, nil
}
