package connectionrecovery

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

// ReportBlocked authenticates the installation key, never an execution session.
// It cannot publish inventory, acquire a token, reconcile or change any binding.
func ReportBlocked(ctx context.Context, c config.Config, credentials execution.Credentials, key ed25519.PrivateKey, remote Remote, reason, operation, endpoint string) error {
	if c.Connection == nil || c.Execution != nil && c.Execution.Enabled {
		return ErrBlocked
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	nonce, err := randomID()
	if err != nil {
		return err
	}
	var op, observedEndpoint any
	if operation != "" {
		op = operation
	}
	if endpoint != "" {
		observedEndpoint = endpoint
	}
	b := c.Connection
	proof := map[string]any{"domain": "neticora-runnerd-restricted-status-v1", "hostId": credentials.Identity.HostId, "keyId": credentials.Identity.KeyId, "keyVersion": credentials.Identity.KeyVersion, "tenantId": credentials.TenantID, "installationId": credentials.InstallationID, "runnerDeploymentId": b.RunnerDeploymentID, "enrollmentRequestId": b.EnrollmentRequestID, "publicKeyFingerprint": b.PublicKeyFingerprint, "reportedSessionEpoch": credentials.Identity.SessionEpoch, "observedBootId": strings.TrimSpace(string(boot)), "observedEndpointIdentity": observedEndpoint, "operationId": op, "reason": reason, "observedAt": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), "nonce": nonce}
	raw, err := peerrecovery.Canonical(proof)
	if err != nil {
		return err
	}
	message, err := protocol.EncodeValidated("SignedConnectionStatus", map[string]any{"proof": proof, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))})
	if err != nil {
		return err
	}
	_, err = remote.Post(ctx, "/connection-status", "", message, "ConnectionStatusReceipt")
	return err
}

// StartupFailure works without opening or repairing a damaged journal. Failure
// to report remains a local startup error; it never creates replacement state.
func StartupFailure(c config.Config, reason string) {
	if c.Connection == nil || c.Execution != nil && c.Execution.Enabled {
		return
	}
	credentials, key, err := execution.ReadCredentials(c.CredentialFile)
	if err != nil {
		return
	}
	defer clear(key)
	remote, err := transport.New(c.ControlPlaneURL, 5*time.Second)
	if err != nil {
		return
	}
	defer remote.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = ReportBlocked(ctx, c, credentials, key, remote, reason, "", "")
}
