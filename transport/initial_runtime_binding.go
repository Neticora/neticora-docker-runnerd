package transport

import "context"

// InitialRuntimeBinding grants no execution authority. The caller verifies the
// independent signature, original credential hash and empty native journal.
func (c *Client) InitialRuntimeBinding(ctx context.Context, token string, request []byte) ([]byte, error) {
	return c.executionCall(ctx, "POST", "/me/initial-runtime-binding", token, request, 200)
}
