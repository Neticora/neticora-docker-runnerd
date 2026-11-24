package transport

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

// KataCacheDecision reads a provider decision from the authenticated control
// plane. The request reuses the bounded execution/generation recovery lookup.
func (c *Client) KataCacheDecision(ctx context.Context, token, id, generation string) (string, error) {
	body, err := protocol.EncodeValidated("RecoveryRequest", map[string]any{
		"entries": []map[string]string{{"executionId": id, "generation": generation}},
	})
	if err != nil {
		return "", err
	}
	var decision string
	_, err = c.post(ctx, "/me/cache/decision", token, body.Bytes(), func(raw []byte) bool {
		canonical, err := protocol.CanonicalizeJSON(raw)
		if err != nil {
			return false
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(canonical, &fields) != nil || len(fields) != 1 {
			return false
		}
		if json.Unmarshal(fields["decision"], &decision) != nil {
			return false
		}
		return decision == "success" || decision == "pending" || decision == "discard"
	})
	if err != nil {
		return "", errors.New("provider cache decision unavailable")
	}
	return decision, nil
}

// KataCacheAccess asks whether the exact issuance can use trusted storage.
func (c *Client) KataCacheAccess(ctx context.Context, token, id, generation string) (bool, error) {
	request, err := protocol.EncodeValidated("RecoveryRequest", map[string]any{
		"entries": []map[string]string{{"executionId": id, "generation": generation}},
	})
	if err != nil {
		return false, err
	}
	var allowed bool
	_, err = c.post(ctx, "/me/cache/access", token, request.Bytes(), func(raw []byte) bool {
		canonical, err := protocol.CanonicalizeJSON(raw)
		if err != nil {
			return false
		}
		switch string(canonical) {
		case `{"allowed":true}`:
			allowed = true
		case `{"allowed":false}`:
		default:
			return false
		}
		return true
	})
	return allowed, err
}

// ReportKataCache advertises placement preference only. It carries no
// eligibility or reservation authority.
func (c *Client) ReportKataCache(ctx context.Context, token, repository, profile string, warm bool) error {
	body, err := json.Marshal(struct {
		Repository string `json:"repository"`
		Profile    string `json:"profile"`
		Warm       bool   `json:"warm"`
	}{repository, profile, warm})
	if err != nil {
		return err
	}
	body, err = protocol.CanonicalizeJSON(body)
	if err != nil {
		return err
	}
	_, err = c.post(ctx, "/me/cache/presence", token, body, func(raw []byte) bool {
		canonical, err := protocol.CanonicalizeJSON(raw)
		return err == nil && string(canonical) == `{"accepted":true}`
	})
	return err
}
