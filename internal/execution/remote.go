package execution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"sync"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/identity"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

type Credentials struct {
	InstallationID   string                `json:"installationId"`
	TenantID         string                `json:"tenantId"`
	EndpointIdentity string                `json:"endpointIdentity"`
	Identity         protocol.HostIdentity `json:"identity"`
	BootID           string                `json:"bootId"`
	PrivateKeyPEM    string                `json:"privateKeyPem"`
}

func ReadCredentials(path string) (Credentials, ed25519.PrivateKey, error) {
	raw, err := hostfs.ReadPrivate(path, 65536)
	if err != nil {
		return Credentials{}, nil, err
	}
	defer clear(raw)
	if _, err = protocol.CanonicalizeJSON(raw); err != nil {
		return Credentials{}, nil, ErrReconcile
	}
	var c Credentials
	// Reject unknown credential fields; JSON decoder/schema checks must precede use.
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 6 {
		return c, nil, ErrReconcile
	}
	for _, k := range []string{"installationId", "tenantId", "endpointIdentity", "identity", "bootId", "privateKeyPem"} {
		if _, ok := fields[k]; !ok {
			return c, nil, ErrReconcile
		}
	}
	if json.Unmarshal(raw, &c) != nil || c.InstallationID == "" || c.TenantID == "" || c.EndpointIdentity == "" || c.BootID == "" {
		return c, nil, ErrReconcile
	}
	rawID, _ := json.Marshal(c.Identity)
	if protocol.ValidateInboundJSON("HostIdentity", rawID) != nil {
		return c, nil, ErrReconcile
	}
	block, rest := pem.Decode([]byte(c.PrivateKeyPEM))
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return c, nil, ErrReconcile
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return c, nil, ErrReconcile
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return c, nil, ErrReconcile
	}
	c.PrivateKeyPEM = ""
	return c, private, nil
}

type HostRemote struct {
	Client           *transport.Client
	Credentials      Credentials
	Key              ed25519.PrivateKey
	Capabilities     protocol.HostCapabilities // Exact independently qualified report.
	PolicyGeneration func() string
	Version          string
	CheckTransport   func() error
	mu               sync.Mutex
	token            string
	expires          time.Time
}

func (r *HostRemote) credential(ctx context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.expires.After(time.Now().Add(30 * time.Second)) {
		return r.token, nil
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	message, err := identity.Assertion(r.Key, r.Credentials.Identity, r.Credentials.BootID, base64.RawURLEncoding.EncodeToString(nonce), time.Now())
	if err != nil {
		return "", err
	}
	raw, err := r.Client.Post(ctx, "/token", "", message, "TokenResponse")
	if err != nil {
		return "", err
	}
	token, err := protocol.DecodeTokenResponse(raw)
	if err != nil {
		return "", err
	}
	r.expires, err = time.Parse(time.RFC3339Nano, token.ExpiresAt)
	if err != nil {
		return "", ErrReconcile
	}
	r.token = token.AccessToken
	return r.token, nil
}
func (r *HostRemote) Recovery(ctx context.Context, lookups []agent.ExecutionCursor) (protocol.RecoveryState, error) {
	t, e := r.credential(ctx)
	if e != nil {
		return protocol.RecoveryState{}, e
	}
	entries := make([]map[string]string, 0, len(lookups))
	for _, key := range lookups {
		entries = append(entries, map[string]string{"executionId": key.ExecutionID, "generation": key.Generation})
	}
	request, e := protocol.EncodeValidated("RecoveryRequest", map[string]any{"entries": entries})
	if e != nil {
		return protocol.RecoveryState{}, e
	}
	return r.Client.Recovery(ctx, t, request)
}
func (r *HostRemote) Commands(ctx context.Context) ([]json.RawMessage, error) {
	t, e := r.credential(ctx)
	if e != nil {
		return nil, e
	}
	return r.Client.Commands(ctx, t)
}
func (r *HostRemote) Ack(ctx context.Context, receipt agent.Receipt) error {
	t, e := r.credential(ctx)
	if e != nil {
		return e
	}
	m, e := protocol.EncodeValidated("CommandAck", map[string]any{"commandId": receipt.CommandID, "payloadHash": receipt.PayloadHash, "generation": receipt.Generation, "acceptance": "durable"})
	if e != nil {
		return e
	}
	return r.Client.AckCommand(ctx, t, m)
}
func (r *HostRemote) Inventory(ctx context.Context, m protocol.Outbound) error {
	t, e := r.credential(ctx)
	if e != nil {
		return e
	}
	return r.Client.Inventory(ctx, t, m)
}
func (r *HostRemote) Events(ctx context.Context, m protocol.Outbound) ([]protocol.EventAck, error) {
	t, e := r.credential(ctx)
	if e != nil {
		return nil, e
	}
	return r.Client.Events(ctx, t, m)
}
func (r *HostRemote) Start(ctx context.Context, m protocol.Outbound) (protocol.StartResponse, error) {
	t, e := r.credential(ctx)
	if e != nil {
		return protocol.StartResponse{}, e
	}
	raw, e := r.Client.Post(ctx, "/me/start", t, m, "StartResponse")
	if e != nil {
		return protocol.StartResponse{}, e
	}
	return protocol.DecodeStartResponse(raw)
}

// Admission refetches the authenticated narrowing proposal for every launch.
// Remote configuration may remove local authority, never add to it.
func (r *HostRemote) Admission(ctx context.Context, s protocol.ExecutionSpec) error {
	t, e := r.credential(ctx)
	if e != nil {
		return e
	}
	raw, e := r.Client.Config(ctx, t)
	if e != nil {
		return e
	}
	c, e := protocol.DecodeConfigResponse(raw)
	if e != nil || !c.AdmissionEnabled || c.Policy.Generation != s.PolicyGeneration {
		return ErrReconcile
	}
	if r.CheckTransport == nil {
		return ErrReconcile
	}
	if e = r.CheckTransport(); e != nil {
		return e
	}
	local := protocol.LocalPolicy{Generation: s.PolicyGeneration, AllowedProfiles: []string{s.ProfileVersion}, AllowedTrustClasses: []protocol.LocalPolicyAllowedTrustClasses{"trusted"}, Limits: s.Resources}
	narrow, e := identity.NarrowPolicy(local, c.Policy)
	if e != nil || len(narrow.AllowedProfiles) != 1 || len(narrow.AllowedTrustClasses) != 1 || narrow.Limits != s.Resources {
		return ErrReconcile
	}
	return nil
}

func (r *HostRemote) Heartbeat(ctx context.Context, generation string) error {
	t, e := r.credential(ctx)
	if e != nil {
		return e
	}
	capabilities := r.Capabilities
	capabilities.ObservedAt = time.Now().UTC().Format(wireTime)
	capabilities.ProbeGeneration = generation
	m, e := protocol.EncodeValidated("HostHeartbeat", map[string]any{"identity": r.Credentials.Identity, "agentVersion": r.Version, "protocolVersion": "1.0.0", "inventoryGeneration": generation, "effectivePolicyGeneration": r.PolicyGeneration(), "capabilities": capabilities})
	if e != nil {
		return e
	}
	_, e = r.Client.Post(ctx, "/me/heartbeat", t, m, "ConfigResponse")
	return e
}

// PeerRecovery uses the same signed short-lived assertions/current host session
// as every recovery request. There is no unauthenticated maintenance transport.
func (r *HostRemote) PeerRecovery(ctx context.Context, id string, complete bool) ([]byte, error) {
	token, err := r.credential(ctx)
	if err != nil {
		return nil, err
	}
	operation := "authorize"
	if complete {
		operation = "complete"
	}
	request, err := protocol.EncodeValidated("PeerRecoveryAccessRequest", map[string]any{"approvalId": id, "operation": operation})
	if err != nil {
		return nil, err
	}
	return r.Client.Post(ctx, "/me/recovery", token, request, "PeerRecoveryAuthorization")
}
