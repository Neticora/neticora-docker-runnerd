package journal

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
)

func connectionIntent(t *testing.T, s *SQLiteStore) protocol.ConnectionResyncIntent {
	t.Helper()
	h := s.Health(context.Background())
	return protocol.ConnectionResyncIntent{Domain: "neticora-runnerd-connection-resync-v1", OperationId: strings.Repeat("a", 48), Identity: protocol.HostIdentity{HostId: "host-a", KeyId: "key-a", KeyVersion: "1", SessionEpoch: "1"}, TenantId: "tenant-a", InstallationId: "install-a", RunnerDeploymentId: "pool-a", EnrollmentRequestId: "enroll-a", PublicKeyFingerprint: strings.Repeat("a", 64), SourceBootId: "old_boot_0123456789", SourceEndpointIdentity: "engine-a", TargetBootId: "new_boot_0123456789", TargetEndpointIdentity: "engine-b", JournalId: h.JournalID, JournalRevision: h.Revision}
}
func TestConnectionRecoveryNeverDiscardsExecutionHistory(t *testing.T) {
	ctx := context.Background()
	s := recovery(t, privateDir(t), Options{})
	storetest.Reconcile(t, s, storetest.Scope, "1")
	if _, err := s.AcceptCommand(ctx, storetest.Scope, storetest.Start(t, "held")); err != nil {
		t.Fatal(err)
	}
	before := s.Health(ctx)
	if err := s.BeginConnectionRecovery(ctx, connectionIntent(t, s)); !errors.Is(err, agent.ErrRecoveryRequired) {
		t.Fatal("execution history allowed", err)
	}
	if _, err := s.ConnectionRecovery(ctx); !errors.Is(err, agent.ErrRecoveryRequired) {
		t.Fatal("obligations ignored", err)
	}
	after := s.Health(ctx)
	if before.Revision != after.Revision {
		t.Fatal("failed recovery changed original obligations")
	}
}
func TestConnectionIntentAnchorInterruptionRequiresExactOriginalReceipt(t *testing.T) {
	ctx := context.Background()
	s := recovery(t, privateDir(t), Options{})
	intent := connectionIntent(t, s)
	dir := s.dir
	s.fault = func(at string) error {
		if at == "after-commit" {
			return errors.New("power loss")
		}
		return nil
	}
	if err := s.BeginConnectionRecovery(ctx, intent); err == nil {
		t.Fatal("fault not injected")
	}
	s.Close()
	reopened, err := OpenRecovery(ctx, dir, testOptions(Options{}))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	pending, err := reopened.ConnectionRecovery(ctx)
	if err != nil || pending == nil || pending.Intent.OperationId != intent.OperationId {
		t.Fatal("original interrupted intent unavailable", err)
	}
	other := intent
	other.OperationId = strings.Repeat("b", 48)
	if err = reopened.BeginConnectionRecovery(ctx, other); err == nil {
		t.Fatal("replaced uncertain intent")
	}
	h, _ := peerrecovery.Hash(intent)
	receipt := protocol.ConnectionResyncResponse{OperationId: intent.OperationId, RequestHash: h, State: "committed", Reason: "observation-only-binding-committed", Identity: intent.Identity, TenantId: intent.TenantId, InstallationId: intent.InstallationId, RunnerDeploymentId: intent.RunnerDeploymentId, BootId: intent.TargetBootId, EndpointIdentity: intent.TargetEndpointIdentity}
	receipt.Identity.SessionEpoch = "2"
	if err = reopened.RecordConnectionRecovery(ctx, intent, receipt, true); err != nil {
		t.Fatal("exact authenticated response could not anchor", err)
	}
	if reopened.Health(ctx).Ready {
		t.Fatal("observation recovery granted execution readiness")
	}
}

func TestConnectionReceiptPersistenceFailuresResumeExactOperation(t *testing.T) {
	for _, phase := range []string{"before-commit", "after-commit", "after-anchor"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			s := recovery(t, privateDir(t), Options{})
			intent := connectionIntent(t, s)
			if err := s.BeginConnectionRecovery(ctx, intent); err != nil {
				t.Fatal(err)
			}
			h, _ := peerrecovery.Hash(intent)
			receipt := protocol.ConnectionResyncResponse{OperationId: intent.OperationId, RequestHash: h, State: "committed", Reason: "observation-only-binding-committed", Identity: intent.Identity, TenantId: intent.TenantId, InstallationId: intent.InstallationId, RunnerDeploymentId: intent.RunnerDeploymentId, BootId: intent.TargetBootId, EndpointIdentity: intent.TargetEndpointIdentity}
			receipt.Identity.SessionEpoch = "2"
			s.fault = func(at string) error {
				if at == phase {
					return errors.New("interrupted local receipt")
				}
				return nil
			}
			if err := s.RecordConnectionRecovery(ctx, intent, receipt, false); err == nil {
				t.Fatal("fault missing")
			}
			dir := s.dir
			s.Close()
			reopened, err := OpenRecovery(ctx, dir, testOptions(Options{}))
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			original, err := reopened.ConnectionRecovery(ctx)
			if err != nil || original == nil || original.Intent.OperationId != intent.OperationId {
				t.Fatal("original record missing", err)
			}
			if err = reopened.RecordConnectionRecovery(ctx, intent, receipt, true); err != nil {
				t.Fatal("exact receipt could not recover", err)
			}
			if reopened.Health(ctx).Ready {
				t.Fatal("local receipt qualified execution")
			}
		})
	}
}
