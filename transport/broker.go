package transport

import (
	"context"
	"encoding/json"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"

	"github.com/Neticora/neticora-docker-runnerd/internal/broker"
)

// BrokerGrant relays a bounded request to the fixed platform issuer. Receipt of
// these bytes does not establish authority: the privileged broker verifies the
// separate pinned issuer key, original binding and current operation scope.
func (c *Client) BrokerGrant(ctx context.Context, token string, request broker.ExecutionGrantRequest) (broker.SignedExecutionGrant, error) {
	if err := request.Validate(); err != nil {
		return broker.SignedExecutionGrant{}, err
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return broker.SignedExecutionGrant{}, err
	}
	raw, err = c.executionCall(ctx, "POST", "/me/broker/grant", token, raw, 200)
	if err != nil {
		return broker.SignedExecutionGrant{}, err
	}
	return broker.DecodeExecutionGrant(raw)
}

func (c *Client) BrokerCommit(ctx context.Context, token string, request broker.ExecutionGrantRequest, grant broker.SignedExecutionGrant) (broker.SignedCommit, error) {
	if request.Validate() != nil {
		return broker.SignedCommit{}, broker.ErrRejected
	}
	raw, err := json.Marshal(broker.CommitRequest{Request: request, Grant: grant})
	if err != nil {
		return broker.SignedCommit{}, err
	}
	raw, err = c.executionCall(ctx, "POST", "/me/broker/commit", token, raw, 200)
	if err != nil {
		return broker.SignedCommit{}, err
	}
	return broker.DecodeCommit(raw)
}
func (c *Client) BrokerBootRecovery(ctx context.Context, token string, challenge broker.SignedBootChallenge) (broker.SignedBootCertificate, error) {
	raw, err := json.Marshal(challenge)
	if err != nil {
		return broker.SignedBootCertificate{}, err
	}
	raw, err = c.executionCall(ctx, "POST", "/me/broker/boot-recovery", token, raw, 200)
	if err != nil {
		return broker.SignedBootCertificate{}, err
	}
	return broker.DecodeBootCertificate(raw)
}

func (c *Client) BrokerDisposalChallenge(ctx context.Context, token string, lookup broker.Lookup) (broker.SignedDisposalChallenge, error) {
	raw, err := json.Marshal(lookup)
	if err != nil {
		return broker.SignedDisposalChallenge{}, err
	}
	raw, err = c.executionCall(ctx, "POST", "/me/broker/disposal/challenge", token, raw, 200)
	if err != nil {
		return broker.SignedDisposalChallenge{}, err
	}
	return broker.DecodeDisposalChallenge(raw)
}
func (c *Client) BrokerDisposal(ctx context.Context, token string, proof broker.SignedDisposal) error {
	raw, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	raw, err = c.executionCall(ctx, "POST", "/me/broker/disposal", token, raw, 200)
	if err != nil {
		return err
	}
	if _, err = protocol.CanonicalizeJSON(raw); err != nil {
		return err
	}
	var result struct {
		State string `json:"state"`
	}
	if json.Unmarshal(raw, &result) != nil || result.State != "VERIFIED" {
		return broker.ErrRejected
	}
	return nil
}
