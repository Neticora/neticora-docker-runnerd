//go:build linux && runnerd_qualification

package execution

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
	"github.com/Neticora/neticora-docker-runnerd/journal"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

type completionLabRemote struct {
	*HostRemote
	phase    string
	ordinary int
}

func (r *completionLabRemote) PeerRecovery(ctx context.Context, id string, complete bool) ([]byte, error) {
	if !complete {
		r.ordinary++
		return r.HostRemote.PeerRecovery(ctx, id, false)
	}
	if r.phase == "before-platform" {
		return nil, errors.New("qualification: completion request interrupted")
	}
	reply, err := r.HostRemote.PeerRecovery(ctx, id, true)
	if err == nil && r.phase == "lost-response" {
		return nil, errors.New("qualification: completion response lost")
	}
	return reply, err
}

// TestRunnerd08LivePeerCompletion uses real durable state and authenticated
// remote authority. The runtime is opened read-only and only empty plans are
// accepted, so this test can never mutate Docker resources.
func TestRunnerd08LivePeerCompletion(t *testing.T) {
	if os.Getenv("RUNNERD08_LIVE_QUALIFICATION") != "1" {
		t.Skip("dedicated Vagrant qualification only")
	}
	if os.Geteuid() == 0 {
		t.Fatal("service identity required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal(err)
	}
	raw, err := hostfs.ReadPrivate("/etc/neticora-runnerd/config.json", config.MaxConfigBytes)
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.Parse(raw)
	if err != nil || c.Execution == nil || c.RuntimeEndpoint != "unix:///run/runnerd07-docker.sock" || c.ControlPlaneURL != "https://platform.scvcluster.neticora.com/api/v1/runner-hosts" {
		t.Fatal("isolated execution configuration required")
	}
	credentials, key, err := ReadCredentials(c.CredentialFile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	raw, err = hostfs.ReadPrivate("/etc/neticora-runnerd/peer-completion-approval.json", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := protocol.DecodeSignedPeerRecoveryApproval(raw)
	if err != nil || len(approval.Manifest.Plan.Executions) != 0 {
		t.Fatal("exact empty-host approval required")
	}
	if approval.Manifest.Plan.InstallationId != credentials.InstallationID || approval.Manifest.Plan.Challenge.Identity != credentials.Identity {
		t.Fatal("identity mismatch")
	}
	public, err := hostfs.ReadPrivate("/etc/neticora-runnerd/peer-recovery-public.pem", 16384)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store, err := journal.OpenRecovery(ctx, c.StateDir, journal.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runtime, err := dockerengine.OpenReadOnly(c.RuntimeEndpoint, credentials.InstallationID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	client, err := transport.NewWithRoots(c.ControlPlaneURL, c.Timeout(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	phase := os.Getenv("RUNNERD08_COMPLETION_PHASE")
	if phase != "before-platform" && phase != "lost-response" && phase != "retry" {
		t.Fatal("unknown phase")
	}
	remote := &completionLabRemote{HostRemote: &HostRemote{Client: client, Credentials: credentials, Key: key, Version: approval.Manifest.Plan.AgentVersion}, phase: phase}
	coordinator := &PeerRecoveryCoordinator{Store: store, Runtime: runtime, Remote: remote, PublicKey: public, Identity: credentials.Identity, TenantID: credentials.TenantID, InstallationID: credentials.InstallationID, BootID: credentials.BootID, AgentVersion: approval.Manifest.Plan.AgentVersion}
	err = coordinator.Apply(ctx, approval)
	if phase != "retry" {
		if err == nil {
			t.Fatal("fault did not interrupt native completion")
		}
		checked, e := peerrecovery.VerifyRecordedApproval(raw, public, approval.Manifest.Plan, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		ready, e := store.PeerRecoveryCompletionReady(ctx, checked)
		if e != nil || !ready {
			t.Fatal("durable completion intent missing", e)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	if phase != "before-platform" && remote.ordinary != 0 {
		t.Fatal("retry reopened ordinary authorization")
	}
	t.Logf("phase=%s ordinary_authorization_calls=%d completion_intent_verified=true", phase, remote.ordinary)
}
