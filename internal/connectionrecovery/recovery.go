// Package connectionrecovery restores observations only. It has no Docker mutation,
// command, ACK, reservation-release or execution-reconciliation interface.
package connectionrecovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

var ErrBlocked = errors.New("connection resynchronization blocked; retain original operation and use administrator recovery")

type Runtime interface {
	Probe(context.Context) (string, error)
	Inventory(context.Context) ([]string, error)
}
type Remote interface {
	Post(context.Context, string, string, protocol.Outbound, string) ([]byte, error)
}
type Binding struct {
	Request protocol.ConnectionResyncIntent   `json:"request"`
	Receipt protocol.ConnectionResyncResponse `json:"receipt"`
}
type Manager struct {
	Store      *journal.SQLiteStore
	Runtime    Runtime
	Remote     Remote
	Config     config.Config
	Key        ed25519.PrivateKey
	Boot       string
	Checkpoint func(string) error
}

func randomID() (string, error) {
	var b [24]byte
	_, err := rand.Read(b[:])
	return hex.EncodeToString(b[:]), err
}
func (m *Manager) checkpoint(name string) error {
	if m.Checkpoint != nil {
		return m.Checkpoint(name)
	}
	return nil
}
func validate(b Binding, original execution.Credentials, c config.Config) error {
	r, s := b.Request, b.Receipt
	if _, err := protocol.EncodeValidated("ConnectionResyncIntent", r); err != nil {
		return ErrBlocked
	}
	if _, err := protocol.EncodeValidated("ConnectionResyncResponse", s); err != nil {
		return ErrBlocked
	}
	if c.Connection == nil || r.InstallationId != original.InstallationID || r.TenantId != original.TenantID || r.Identity.HostId != original.Identity.HostId || r.Identity.KeyId != original.Identity.KeyId || r.Identity.KeyVersion != original.Identity.KeyVersion || r.RunnerDeploymentId != c.Connection.RunnerDeploymentID || r.EnrollmentRequestId != c.Connection.EnrollmentRequestID || r.PublicKeyFingerprint != c.Connection.PublicKeyFingerprint {
		return ErrBlocked
	}
	h, err := peerrecovery.Hash(r)
	if err != nil || s.State != "committed" || s.RequestHash != h || s.OperationId != r.OperationId || s.InstallationId != r.InstallationId || s.TenantId != r.TenantId || s.RunnerDeploymentId != r.RunnerDeploymentId || s.BootId != r.TargetBootId || s.EndpointIdentity != r.TargetEndpointIdentity {
		return ErrBlocked
	}
	next := r.Identity
	a, err := strconv.ParseUint(next.SessionEpoch, 10, 64)
	if err != nil || a == ^uint64(0) {
		return ErrBlocked
	}
	next.SessionEpoch = strconv.FormatUint(a+1, 10)
	if s.Identity != next {
		return ErrBlocked
	}
	return nil
}

// Load is an observation-only cache. The platform reauthenticates its epoch using
// the original private key; execution.Open never reads or trusts this overlay.
func Load(c config.Config, original execution.Credentials) (execution.Credentials, error) {
	path := filepath.Join(c.StateDir, "connection-binding.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err = hostfs.CheckAncestors(c.StateDir); err != nil {
			return original, err
		}
		return original, nil
	}
	raw, err := hostfs.ReadPrivate(path, 65536)
	if errors.Is(err, os.ErrNotExist) {
		return original, nil
	}
	if err != nil {
		return original, ErrBlocked
	}
	var b Binding
	if json.Unmarshal(raw, &b) != nil || validate(b, original, c) != nil {
		return original, ErrBlocked
	}
	original.Identity = b.Receipt.Identity
	original.BootID = b.Receipt.BootId
	original.EndpointIdentity = b.Receipt.EndpointIdentity
	return original, nil
}
func (m *Manager) storeBinding(b Binding) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	root, err := hostfs.OpenState(m.Config.StateDir)
	if err != nil {
		return err
	}
	defer root.Close()
	name, err := randomID()
	if err != nil {
		return err
	}
	name = ".connection-binding-" + name
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(name)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = m.checkpoint("before-binding-rename"); err != nil {
		return err
	}
	if err = root.Rename(name, "connection-binding.json"); err != nil {
		return err
	}
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return err
	}
	return m.checkpoint("after-binding-sync")
}

// Step resumes one exact persisted transition. A newer boot during an ambiguous
// transition is blocked rather than substituted. A committed response grants no
// execution readiness and the original credential/key file is never rewritten.
func (m *Manager) Step(ctx context.Context, original execution.Credentials) (execution.Credentials, string, string, error) {
	effective, err := Load(m.Config, original)
	if err != nil {
		return original, "", "binding-unavailable", err
	}
	record, err := m.Store.ConnectionRecovery(ctx)
	if err != nil {
		return effective, "", "journal-obligations-or-integrity", err
	}
	endpoint, err := m.Runtime.Probe(ctx)
	if err != nil {
		return effective, "", "runtime-unavailable", err
	}
	pending := record != nil && (!record.Completed || m.Store.Health(ctx).Reason == "anchor-reconciliation-required")
	if !pending && effective.BootID == m.Boot && effective.EndpointIdentity == endpoint {
		return effective, "", "current", nil
	}
	if m.Config.Connection == nil || m.Config.Execution != nil && m.Config.Execution.Enabled {
		return effective, "", "execution-mode-requires-peer-recovery", ErrBlocked
	}
	ids, err := m.Runtime.Inventory(ctx)
	if err != nil || len(ids) != 0 {
		return effective, "", "unknown-runtime-resources", ErrBlocked
	}
	after, err := m.Runtime.Probe(ctx)
	if err != nil || after != endpoint {
		return effective, "", "runtime-continuity-lost", ErrBlocked
	}
	if !pending {
		id, err := randomID()
		if err != nil {
			return effective, "", "intent-unavailable", err
		}
		health := m.Store.Health(ctx)
		b := m.Config.Connection
		request := protocol.ConnectionResyncIntent{Domain: "neticora-runnerd-connection-resync-v1", OperationId: id, Identity: effective.Identity, TenantId: effective.TenantID, InstallationId: effective.InstallationID, RunnerDeploymentId: b.RunnerDeploymentID, EnrollmentRequestId: b.EnrollmentRequestID, PublicKeyFingerprint: b.PublicKeyFingerprint, SourceBootId: effective.BootID, SourceEndpointIdentity: effective.EndpointIdentity, TargetBootId: m.Boot, TargetEndpointIdentity: endpoint, JournalId: health.JournalID, JournalRevision: health.Revision}
		if err = m.Store.BeginConnectionRecovery(ctx, request); err != nil {
			return effective, id, "intent-persistence-failed", err
		}
		record = &journal.ConnectionRecovery{Intent: request}
	}
	r := record.Intent
	id := r.OperationId
	if r.TargetBootId != m.Boot || r.TargetEndpointIdentity != endpoint {
		return effective, id, "pending-target-changed", ErrBlocked
	}
	// Revalidate source installation and exact current intent on every retry.
	if r.InstallationId != original.InstallationID || r.TenantId != original.TenantID || r.Identity.HostId != original.Identity.HostId || r.Identity.KeyId != original.Identity.KeyId || r.Identity.KeyVersion != original.Identity.KeyVersion {
		return effective, id, "intent-binding-mismatch", ErrBlocked
	}
	if err = m.checkpoint("before-request"); err != nil {
		return effective, id, "request-interrupted", err
	}
	nonce, err := randomID()
	if err != nil {
		return effective, id, "proof-unavailable", err
	}
	proof := protocol.ConnectionResyncProof{Domain: "neticora-runnerd-connection-resync-proof-v1", Request: r, IssuedAt: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), Nonce: nonce, JournalEmpty: true, InventoryComplete: true, OwnedResourceIds: []string{}}
	canonical, err := peerrecovery.Canonical(proof)
	if err != nil {
		return effective, id, "proof-invalid", err
	}
	message, err := protocol.EncodeValidated("SignedConnectionResyncRequest", protocol.SignedConnectionResyncRequest{Proof: proof, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(m.Key, canonical))})
	if err != nil {
		return effective, id, "proof-invalid", err
	}
	raw, err := m.Remote.Post(ctx, "/connection-resync", "", message, "ConnectionResyncResponse")
	if err != nil {
		return effective, id, "platform-unavailable-or-rejected", err
	}
	response, err := protocol.DecodeConnectionResyncResponse(raw)
	if err != nil {
		return effective, id, "response-invalid", err
	}
	h, _ := peerrecovery.Hash(r)
	if response.OperationId != id || response.RequestHash != h {
		return effective, id, "response-binding-mismatch", ErrBlocked
	}
	if response.State != "committed" {
		return effective, id, response.Reason, ErrBlocked
	}
	binding := Binding{Request: r, Receipt: response}
	if validate(binding, original, m.Config) != nil {
		return effective, id, "committed-binding-invalid", ErrBlocked
	}
	if err = m.checkpoint("after-platform-acceptance"); err != nil {
		return effective, id, "local-acceptance-interrupted", err
	}
	// Authenticate the same endpoint after remote acceptance and before local commit.
	after, err = m.Runtime.Probe(ctx)
	if err != nil || after != endpoint {
		return effective, id, "post-acceptance-continuity-lost", ErrBlocked
	}
	ids, err = m.Runtime.Inventory(ctx)
	if err != nil || len(ids) != 0 {
		return effective, id, "post-acceptance-resources-uncertain", ErrBlocked
	}
	after, err = m.Runtime.Probe(ctx)
	if err != nil || after != endpoint {
		return effective, id, "post-acceptance-continuity-lost", ErrBlocked
	}
	if err = m.Store.RecordConnectionRecovery(ctx, r, response, false); err != nil {
		return effective, id, "receipt-persistence-failed", err
	}
	if err = m.storeBinding(binding); err != nil {
		return effective, id, "binding-persistence-failed", err
	}
	if err = m.Store.RecordConnectionRecovery(ctx, r, response, true); err != nil {
		return effective, id, "completion-persistence-failed", err
	}
	effective, err = Load(m.Config, original)
	return effective, id, "committed", err
}
