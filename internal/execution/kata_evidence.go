package execution

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

// KataEvidence is an owner-only, read-only export. It binds a root-observer
// witness to the immutable native command and ACK state with the registered host
// key. Never export bootstrap, credentials, start requests or raw command bytes.
func (c *Controller) KataEvidence(ctx context.Context, id, generation string) (any, error) {
	if c.Kata == nil || len(c.SigningKey) != ed25519.PrivateKeySize {
		return nil, ErrReconcile
	}
	e, err := c.Store.PeerRecoveryExecution(ctx, id, generation)
	if err != nil || e.State != "cleaned" || e.CleanupPending || e.LastSequence != e.AckSequence {
		return nil, ErrReconcile
	}
	plan, err := c.plan(e)
	if err != nil {
		return nil, err
	}
	start, err := protocol.DecodeStartCommand(e.Command)
	if err != nil {
		return nil, err
	}
	ref, err := protocol.DecodeRuntimeRef(e.RuntimeRef)
	if err != nil || ref.ExecutionId != id || ref.Generation != generation || ref.SpecHash != e.Identity.SpecHash || ref.Scope != c.Scope.EndpointIdentity {
		return nil, ErrReconcile
	}
	physical, err := c.Kata.PhysicalEvidence(ctx, ref.ResourceId, plan)
	if err != nil {
		return nil, err
	}
	// Re-read after host inspection; a changed journal cannot be correlated using
	// the earlier snapshot. Any uncertainty rejects the export, not the store.
	again, err := c.Store.PeerRecoveryExecution(ctx, id, generation)
	if err != nil || again.State != e.State || again.CleanupPending || again.LastSequence != e.LastSequence || again.AckSequence != e.AckSequence || string(again.Command) != string(e.Command) || string(again.RuntimeRef) != string(e.RuntimeRef) {
		return nil, ErrReconcile
	}
	manifest := map[string]any{
		"version": "runnerd09-host-evidence-v1", "observedAt": time.Now().UTC().Format(time.RFC3339Nano),
		"agentVersion": Version(), "tenantId": c.Scope.TenantID, "hostId": c.Scope.HostID, "installationId": c.Scope.InstallationID,
		"sessionEpoch": c.Scope.SessionEpoch, "keyId": c.Authority.KeyID, "endpointIdentity": c.Scope.EndpointIdentity,
		"executionId": id, "generation": generation, "attemptId": e.Identity.AttemptID, "specHash": e.Identity.SpecHash,
		"profileVersion": c.Kata.ID, "spec": start.Spec, "resourceId": ref.ResourceId, "state": e.State,
		"lastSequence": e.LastSequence, "ackSequence": e.AckSequence, "physical": physical,
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	raw, err = protocol.CanonicalizeJSON(raw)
	if err != nil {
		return nil, err
	}
	return map[string]any{"manifest": manifest, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.SigningKey, raw))}, nil
}
