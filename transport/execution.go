package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

// executionCall has fixed callers/paths, bounded bodies and strict response
// contracts. It does not retry side effects or include server errors in logs.
func (c *Client) executionCall(ctx context.Context, method, path, token string, body []byte, status int) ([]byte, error) {
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("host credential unavailable")
	}
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("protocol request unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("protocol request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != status || (res.Header.Get("Content-Encoding") != "" && res.Header.Get("Content-Encoding") != "identity") {
		return nil, errors.New("protocol response rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, protocol.MaxWireBytes+1))
	if err != nil || len(raw) > protocol.MaxWireBytes {
		return nil, errors.New("protocol response oversized or unreadable")
	}
	if status == 204 && len(raw) != 0 {
		return nil, errors.New("invalid empty protocol response")
	}
	return raw, nil
}
func (c *Client) Commands(ctx context.Context, token string) ([]json.RawMessage, error) {
	raw, err := c.executionCall(ctx, "GET", "/me/commands", token, nil, 200)
	if err != nil {
		return nil, err
	}
	if _, err = protocol.CanonicalizeJSON(raw); err != nil {
		return nil, err
	}
	var rows []json.RawMessage
	if json.Unmarshal(raw, &rows) != nil || rows == nil || len(rows) > 20 {
		return nil, errors.New("invalid command page")
	}
	for _, r := range rows {
		if protocol.ValidateInboundJSON("HostCommand", r) != nil {
			return nil, errors.New("invalid host command")
		}
	}
	return rows, nil
}
func (c *Client) AckCommand(ctx context.Context, token string, message protocol.Outbound) error {
	_, err := c.executionCall(ctx, "POST", "/me/commands/ack", token, message.Bytes(), 204)
	return err
}
func (c *Client) Inventory(ctx context.Context, token string, message protocol.Outbound) error {
	_, err := c.executionCall(ctx, "POST", "/me/inventory", token, message.Bytes(), 204)
	return err
}
func (c *Client) Events(ctx context.Context, token string, message protocol.Outbound) ([]protocol.EventAck, error) {
	raw, err := c.executionCall(ctx, "POST", "/me/events", token, message.Bytes(), 200)
	if err != nil {
		return nil, err
	}
	if _, err = protocol.CanonicalizeJSON(raw); err != nil {
		return nil, err
	}
	var rows []json.RawMessage
	if json.Unmarshal(raw, &rows) != nil || rows == nil || len(rows) > 100 {
		return nil, errors.New("invalid ACK page")
	}
	acks := make([]protocol.EventAck, 0, len(rows))
	for _, r := range rows {
		a, e := protocol.DecodeEventAck(r)
		if e != nil {
			return nil, e
		}
		acks = append(acks, a)
	}
	return acks, nil
}
func (c *Client) Recovery(ctx context.Context, token string, request protocol.Outbound) (protocol.RecoveryState, error) {
	if err := protocol.ValidateInboundJSON("RecoveryRequest", request.Bytes()); err != nil {
		return protocol.RecoveryState{}, err
	}
	raw, err := c.executionCall(ctx, "POST", "/me/recovery", token, request.Bytes(), 200)
	if err != nil {
		return protocol.RecoveryState{}, err
	}
	return protocol.DecodeRecoveryState(raw)
}
