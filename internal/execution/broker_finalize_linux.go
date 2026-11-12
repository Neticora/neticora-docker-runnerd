//go:build linux

package execution

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	"github.com/Neticora/neticora-docker-runnerd/journal"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

// FinalizeBrokerRecovery uses the existing platform/broker authorization and
// native journal. The daemon must be stopped: OpenRecovery takes its exclusive
// installation lock. Credentials and original scope are never rewritten.
func FinalizeBrokerRecovery(ctx context.Context, c config.Config) ([]byte, error) {
	x := c.Execution
	if x == nil || !x.Enabled || x.BrokerSocket == "" || os.Geteuid() == 0 {
		return nil, ErrReconcile
	}
	if err := checkBrokerContainment(c.RuntimeEndpoint); err != nil {
		return nil, err
	}
	if err := persistRecoveryDrain(c.StateDir); err != nil {
		return nil, err
	}
	credentials, key, err := ReadCredentials(c.CredentialFile)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	policy, err := NewPolicyFile(x.PolicyFile)
	if err != nil || policy.Get().UID() != os.Geteuid() {
		return nil, ErrReconcile
	}
	store, err := journal.OpenRecovery(ctx, c.StateDir, journal.Options{ReservationLimits: policy.Get().Limits()})
	if err != nil {
		return nil, err
	}
	defer store.Close()
	scope, err := store.PeerRecoveryScope(ctx)
	if err != nil || scope != (agent.StoreScope{InstallationID: credentials.InstallationID, TenantID: credentials.TenantID, HostID: credentials.Identity.HostId, SessionEpoch: credentials.Identity.SessionEpoch, EndpointIdentity: credentials.EndpointIdentity}) {
		return nil, ErrReconcile
	}
	var ca []byte
	if x.CustomCAFile != "" {
		ca, err = hostfs.ReadPrivate(x.CustomCAFile, 1<<20)
		if err != nil {
			return nil, err
		}
	}
	client, err := transport.NewWithRoots(c.ControlPlaneURL, c.Timeout(), ca)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	remote := &HostRemote{Client: client, Credentials: credentials, Key: key, Version: Version(), PolicyGeneration: func() string { return policy.Get().Generation() }}
	controller := &Controller{recoveryOnly: true, Store: store, Remote: remote, SigningKey: key, Scope: scope, Authority: journal.Authority{TenantID: scope.TenantID, HostID: scope.HostID, SessionEpoch: scope.SessionEpoch, EndpointIdentity: scope.EndpointIdentity, KeyID: credentials.Identity.KeyId}, Profile: standardlinux.Settings{ImageRepository: x.ImageRepository, NetworkID: x.NetworkID, BootstrapRoot: x.BootstrapRoot, RunnerUID: os.Geteuid(), PidsLimit: x.PidsLimit}, Policy: policy.Get, KeysDirectory: x.KeysDirectory, Organization: x.Organization, Repository: x.Repository, Pool: x.Pool, Drained: func() bool { return true }, cancelled: map[agent.ExecutionCursor]bool{}}
	controller.Runtime = brokerRuntimeFor(controller, remote, x.BrokerSocket)
	controller.heartbeatGeneration.Store("1")
	if observed, err := controller.Runtime.Probe(ctx); err != nil || observed != scope.EndpointIdentity {
		return nil, ErrReconcile
	}
	if _, err = controller.refresh(ctx); err != nil {
		return nil, err
	}
	for {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		commands, err := remote.Commands(ctx)
		if err != nil {
			return nil, err
		}
		for _, raw := range commands {
			var control struct{ Kind, ExecutionID, Generation string }
			if json.Unmarshal(raw, &control) != nil {
				return nil, ErrReconcile
			}
			if control.Kind != "cancel" && control.Kind != "cleanup" {
				continue
			}
			existing, err := store.PeerRecoveryExecution(ctx, control.ExecutionID, control.Generation)
			if err != nil || existing.Identity.InstallationID != scope.InstallationID || existing.Identity.HostID != scope.HostID || existing.Identity.TenantID != scope.TenantID {
				continue
			}
			receipt, err := controller.accept(ctx, raw)
			if err != nil {
				return nil, err
			}
			if err = remote.Ack(ctx, receipt); err != nil {
				return nil, err
			}
		}
		if err = controller.reconcile(ctx); err != nil {
			return nil, err
		}
		rows, err := controller.executions(ctx)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if err = controller.flushExecutionEvents(ctx, row.Identity.ExecutionID, row.Identity.Generation); err != nil {
				return nil, err
			}
		}
		rows, err = controller.executions(ctx)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			return json.Marshal(map[string]any{"state": "completed-drained", "admissionEnabled": false, "credentialsChanged": false})
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
