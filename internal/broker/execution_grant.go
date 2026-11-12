package broker

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

const ExecutionGrantVersion = "runnerd-broker-execution-v1"
const executionGrantDomain = "neticora-runnerd-broker-execution-grant-v1\n"

type ExecutionGrantRequest struct {
	Version          string `json:"version"`
	Operation        string `json:"operation"`
	OperationID      string `json:"operationId"`
	ExecutionID      string `json:"executionId"`
	Generation       string `json:"generation"`
	ExpectedRevision string `json:"expectedRevision"`
	ResourceID       string `json:"resourceId"`
	Challenge        string `json:"challenge"`
}

type ExecutionGrant struct {
	Version          string                 `json:"version"`
	Audience         string                 `json:"audience"`
	Operation        string                 `json:"operation"`
	OperationID      string                 `json:"operationId"`
	ExpectedRevision string                 `json:"expectedRevision"`
	ExpectedState    string                 `json:"expectedState"`
	ResourceID       string                 `json:"resourceId"`
	Challenge        string                 `json:"challenge"`
	Binding          Binding                `json:"binding"`
	Spec             protocol.ExecutionSpec `json:"spec"`
	NotBefore        string                 `json:"notBefore"`
	ExpiresAt        string                 `json:"expiresAt"`
}

type SignedExecutionGrant struct {
	Grant     ExecutionGrant `json:"grant"`
	Signature string         `json:"signature"`
}

func DecodeExecutionGrant(raw []byte) (SignedExecutionGrant, error) {
	var value SignedExecutionGrant
	err := decode(raw, &value)
	return value, err
}

func counter(s string) bool {
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && strconv.FormatUint(n, 10) == s
}

func executionState(operation string) string {
	switch operation {
	case "PrepareImage", "CreateExecution", "DisposeUnstarted":
		return "ALLOCATED"
	case "StartExecution":
		return "PREPARED"
	case "StopExecution":
		return "STOPPING"
	case "RemoveExecution":
		return "STOPPED"
	}
	return ""
}

func canonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return protocol.CanonicalizeJSON(raw)
}

// OperationIdentity does not depend on challenge, expiry or controller randomness:
// renewed grants cannot allocate a new operation for the same physical effect.
func (r ExecutionGrantRequest) OperationIdentity() string {
	raw, err := canonical(map[string]string{"version": ExecutionGrantVersion, "operation": r.Operation, "executionId": r.ExecutionID, "generation": r.Generation, "expectedRevision": r.ExpectedRevision, "resourceId": r.ResourceID})
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func (r ExecutionGrantRequest) Validate() error {
	if r.Version != ExecutionGrantVersion || executionState(r.Operation) == "" || !digest(r.OperationID) || r.OperationID != r.OperationIdentity() || !digest(r.Challenge) || !counter(r.Generation) || r.Generation == "0" || !counter(r.ExpectedRevision) || r.ExecutionID == "" || len(r.ExecutionID) > 128 {
		return ErrRejected
	}
	for _, c := range r.ExecutionID {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return ErrRejected
		}
	}
	if r.Operation == "PrepareImage" || r.Operation == "CreateExecution" || r.Operation == "DisposeUnstarted" {
		if r.ResourceID != "" {
			return ErrRejected
		}
	} else if !digest(r.ResourceID) {
		return ErrRejected
	}
	return nil
}

// VerifyExecutionGrant validates independent platform authority, not local peer
// credentials. Callers must separately check protected resource/revision/state,
// cancellation and current revocation before any future runtime effect.
func VerifyExecutionGrant(s SignedExecutionGrant, r ExecutionGrantRequest, key ed25519.PublicKey, scope Binding, now time.Time) error {
	if r.Validate() != nil || len(key) != ed25519.PublicKeySize {
		return ErrRejected
	}
	g, b := s.Grant, s.Grant.Binding
	if g.Version != ExecutionGrantVersion || g.Audience != "neticora-broker:"+scope.InstallationID || g.Operation != r.Operation || g.OperationID != r.OperationID || g.ResourceID != r.ResourceID || g.ExpectedRevision != r.ExpectedRevision || g.ExpectedState != executionState(r.Operation) || g.Challenge != r.Challenge || !b.valid() {
		return ErrRejected
	}
	if b.InstallationID != scope.InstallationID || b.TenantID != scope.TenantID || b.HostID != scope.HostID || b.SessionEpoch != scope.SessionEpoch || b.EndpointIdentity != scope.EndpointIdentity || b.ExecutionID != r.ExecutionID || b.Generation != r.Generation {
		return ErrRejected
	}
	start, e1 := time.Parse(time.RFC3339Nano, g.NotBefore)
	end, e2 := time.Parse(time.RFC3339Nano, g.ExpiresAt)
	if e1 != nil || e2 != nil || !end.After(start) || end.Sub(start) > 15*time.Second || now.Before(start) || !now.Before(end) {
		return ErrRejected
	}
	raw, err := canonical(g)
	if err != nil {
		return ErrRejected
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(key, append([]byte(executionGrantDomain), raw...), signature) {
		return ErrRejected
	}
	raw, err = json.Marshal(g.Spec)
	if err != nil || protocol.ValidateInboundJSON("ExecutionSpec", raw) != nil {
		return ErrRejected
	}
	spec, err := protocol.DecodeExecutionSpec(raw)
	if err != nil || spec.ExecutionId != b.ExecutionID || spec.Generation != b.Generation || spec.AttemptId != b.AttemptID || spec.SpecHash != b.SpecHash || spec.IsolationProfile != "standard" || spec.TemplateVersion != "linux-github-process-v1" || spec.RuntimeEngine != "docker" || spec.ExecutionBackend != "customer-host" {
		return ErrRejected
	}
	if r.Operation == "PrepareImage" || r.Operation == "CreateExecution" || r.Operation == "StartExecution" {
		expires, err := time.Parse(time.RFC3339Nano, spec.AuthorizationExpiresAt)
		if err != nil || end.After(expires) || !now.Before(expires) {
			return ErrRejected
		}
	}
	return nil
}

// IntentPayload excludes freshness evidence: a renewed signature may reconcile
// only the same immutable operation; it cannot silently replace its payload.
func (g ExecutionGrant) IntentPayload() ([]byte, error) {
	return canonical(map[string]any{"version": g.Version, "operation": g.Operation, "operationId": g.OperationID, "expectedRevision": g.ExpectedRevision, "expectedState": g.ExpectedState, "resourceId": g.ResourceID, "binding": g.Binding, "spec": g.Spec})
}
