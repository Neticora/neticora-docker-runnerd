//go:build linux

package execution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

type recoveryRuntimeTest struct {
	*fakeRuntime
	endpoint   string
	loseRemove bool
}

func (r *recoveryRuntimeTest) Probe(context.Context) (string, error) { return r.endpoint, nil }
func (r *recoveryRuntimeTest) RecoverStop(ctx context.Context, id string, p dockerengine.Plan, auth dockerengine.RecoveryAuthority) error {
	a, err := auth(ctx)
	if err != nil {
		return err
	}
	value, err := a.Approval().Value()
	if err != nil || !a.Current(time.Now()) || value.Manifest.Plan.TargetEndpointIdentity != r.endpoint {
		return dockerengine.ErrUnavailable
	}
	if r.object == nil || id != r.object.ID {
		return dockerengine.ErrAbsent
	}
	if r.object.State == "running" {
		return r.fakeRuntime.Stop(ctx, id, p)
	}
	return nil
}
func (r *recoveryRuntimeTest) RecoverRemove(ctx context.Context, id string, p dockerengine.Plan, auth dockerengine.RecoveryAuthority) error {
	a, err := auth(ctx)
	if err != nil {
		return err
	}
	value, err := a.Approval().Value()
	if err != nil || !a.Current(time.Now()) || value.Manifest.Plan.TargetEndpointIdentity != r.endpoint {
		return dockerengine.ErrUnavailable
	}
	if r.object == nil || id != r.object.ID || r.object.State == "running" {
		return dockerengine.ErrConflict
	}
	if err = r.fakeRuntime.Remove(ctx, id, p); err != nil {
		return err
	}
	if r.loseRemove {
		r.loseRemove = false
		return dockerengine.ErrUnavailable
	}
	return nil
}

type recoveryRemoteTest struct {
	t                                    *testing.T
	runtime                              *recoveryRuntimeTest
	start                                protocol.StartCommand
	identity                             protocol.HostIdentity
	endpoint, inventory                  string
	approval                             protocol.SignedPeerRecoveryApproval
	watermark                            string
	events                               map[string]string
	lastState                            string
	controls                             []json.RawMessage
	deny, loseEventReply                 bool
	completionRequests, acknowledgements int
}

func (r *recoveryRemoteTest) Recovery(context.Context, []agent.ExecutionCursor) (protocol.RecoveryState, error) {
	return protocol.RecoveryState{Identity: r.identity, EndpointIdentity: r.endpoint, InventoryGeneration: r.inventory, Entries: []protocol.RecoveryEntry{{ExecutionId: r.start.Spec.ExecutionId, Generation: r.start.Generation, CommandId: r.start.CommandId, SpecHash: r.start.Spec.SpecHash, ContiguousSequence: r.watermark}}}, nil
}
func (r *recoveryRemoteTest) PeerRecovery(_ context.Context, id string, complete bool) ([]byte, error) {
	if r.deny || id != r.approval.Manifest.ApprovalId {
		return nil, ErrReconcile
	}
	status := protocol.PeerRecoveryAuthorizationStatus("APPLIED")
	if complete {
		if r.runtime.object != nil || r.lastState != "cleaned" || r.acknowledgements == 0 {
			return nil, ErrReconcile
		}
		status = "COMPLETED"
		r.completionRequests++
	}
	return json.Marshal(protocol.PeerRecoveryAuthorization{Approval: r.approval, Identity: r.identity, Status: status, VerifiedAt: time.Now().UTC().Format(wireTime), ServerWatermarks: []protocol.EventAck{{ExecutionId: r.start.Spec.ExecutionId, Generation: r.start.Generation, ContiguousSequence: r.watermark}}})
}
func (r *recoveryRemoteTest) Inventory(_ context.Context, m protocol.Outbound) error {
	snapshot, err := protocol.DecodeInventorySnapshot(m.Bytes())
	if err != nil || snapshot.EndpointIdentity != r.endpoint {
		return ErrReconcile
	}
	r.inventory = snapshot.InventoryGeneration
	return nil
}
func (r *recoveryRemoteTest) Events(_ context.Context, m protocol.Outbound) ([]protocol.EventAck, error) {
	var batch struct {
		Events []json.RawMessage `json:"events"`
	}
	if json.Unmarshal(m.Bytes(), &batch) != nil {
		return nil, ErrReconcile
	}
	for _, raw := range batch.Events {
		if protocol.ValidateInboundJSON("HostEvent", raw) != nil {
			return nil, ErrReconcile
		}
		var e struct {
			eventDocumentForRecovery
			Observation *struct {
				State string `json:"state"`
			} `json:"observation"`
		}
		if json.Unmarshal(raw, &e) != nil {
			return nil, ErrReconcile
		}
		if digest, ok := r.events[e.Sequence]; ok {
			if digest != e.PayloadHash {
				return nil, ErrReconcile
			}
			continue
		}
		if paddedCounter(e.Sequence) <= paddedCounter(r.watermark) {
			return nil, ErrReconcile
		}
		r.events[e.Sequence] = e.PayloadHash
		r.watermark = e.Sequence
		if e.Observation != nil {
			if e.Observation.State == "cleaned" && (r.runtime.object != nil || r.lastState != "cleanup-pending") {
				return nil, ErrReconcile
			}
			r.lastState = e.Observation.State
			if r.lastState == "cleanup-pending" {
				r.controls = []json.RawMessage{storetest.Encode(r.t, "HostCommand", map[string]any{"commandId": "recovery-cleanup", "kind": "cleanup", "executionId": r.start.Spec.ExecutionId, "generation": r.start.Generation})}
			}
		}
	}
	if r.loseEventReply {
		r.loseEventReply = false
		return nil, ErrReconcile
	}
	return []protocol.EventAck{{ExecutionId: r.start.Spec.ExecutionId, Generation: r.start.Generation, ContiguousSequence: r.watermark}}, nil
}
func (r *recoveryRemoteTest) Commands(context.Context) ([]json.RawMessage, error) {
	return r.controls, nil
}
func (r *recoveryRemoteTest) Ack(context.Context, agent.Receipt) error {
	r.acknowledgements++
	return nil
}

func recoveryCoordinatorTest(t *testing.T) (*PeerRecoveryCoordinator, *recoveryRuntimeTest, *recoveryRemoteTest, ed25519.PrivateKey) {
	t.Helper()
	original, r, remote, e := setup(t)
	if err := original.execution(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	runtime := &recoveryRuntimeTest{fakeRuntime: r, endpoint: "engine-replacement"}
	server := &recoveryRemoteTest{t: t, runtime: runtime, start: remote.start, identity: protocol.HostIdentity{HostId: "host-a", KeyId: "key-a", KeyVersion: "1", SessionEpoch: "2"}, endpoint: "engine-a", inventory: "1", watermark: "0", events: map[string]string{}}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	c := &PeerRecoveryCoordinator{Store: original.Store, Runtime: runtime, Remote: server, Profile: original.Profile, PublicKey: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), Identity: server.identity, TenantID: "tenant-a", InstallationID: "install-a", BootID: "actual-recovery-boot-identity", AgentVersion: "recovery-build"}
	return c, runtime, server, key
}
func approveRecoveryTest(t *testing.T, c *PeerRecoveryCoordinator, r *recoveryRemoteTest, key ed25519.PrivateKey, action string) protocol.SignedPeerRecoveryApproval {
	t.Helper()
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := protocol.PeerRecoveryChallenge{ChallengeId: "challenge-a", Nonce: strings.Repeat("n", 43), TenantId: c.TenantID, Identity: c.Identity, ServerSnapshotHash: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Format(wireTime)}
	signed, err := c.Propose(context.Background(), challenge, hostKey)
	if err != nil {
		t.Fatal("proposal", err)
	}
	digest, _ := peerrecovery.Hash(signed.Plan)
	manifest := protocol.PeerRecoveryApprovalManifest{Domain: "neticora-runnerd-peer-recovery-approval-v1", ApprovalId: "approval-a", Plan: signed.Plan, PlanHash: digest, Decisions: []protocol.PeerRecoveryDecision{{ExecutionId: r.start.Spec.ExecutionId, Generation: r.start.Generation, Action: protocol.PeerRecoveryDecisionAction(action)}}, IssuedAt: time.Now().UTC().Format(wireTime), ExpiresAt: time.Now().Add(5 * time.Minute).UTC().Format(wireTime), AuditReference: "Independent operator reviewed recovery"}
	raw, _ := peerrecovery.Canonical(manifest)
	a := protocol.SignedPeerRecoveryApproval{Manifest: manifest, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))}
	r.approval = a
	r.endpoint = c.Runtime.(*recoveryRuntimeTest).endpoint
	return a
}

func TestPeerRecoveryCoordinatorNeverStartsAndKeepsOriginFacts(t *testing.T) {
	for _, state := range []string{"running", "exited"} {
		t.Run(state, func(t *testing.T) {
			c, r, remote, key := recoveryCoordinatorTest(t)
			r.object.State = state
			a := approveRecoveryTest(t, c, remote, key, "cleanup")
			before, err := c.Store.PeerRecoveryExecution(context.Background(), remote.start.Spec.ExecutionId, "1")
			if err != nil {
				t.Fatal(err)
			}
			if err = c.Apply(context.Background(), a); err != nil {
				native, _ := c.Store.PeerRecoveryExecution(context.Background(), remote.start.Spec.ExecutionId, "1")
				t.Fatal(err, "native", native.State, native.LastSequence, native.AckSequence, "server", remote.lastState, remote.watermark, "ops", r.stops, r.removes, "health", c.Store.Health(context.Background()))
			}
			after, err := c.Store.PeerRecoveryExecution(context.Background(), remote.start.Spec.ExecutionId, "1")
			if err != nil {
				t.Fatal(err)
			}
			if after.State != "cleaned" || after.CleanupPending || after.LastSequence != after.AckSequence || r.object != nil || r.starts != 1 || r.creates != 1 || remote.completionRequests != 1 || string(before.Command) != string(after.Command) {
				t.Fatal("unsafe recovery completion", after.State, r.starts, r.creates)
			}
			if err := c.Apply(context.Background(), a); err != nil {
				t.Fatal("completed retry failed", err)
			}
			if r.removes != 1 || r.starts != 1 || r.creates != 1 {
				t.Fatal("completed retry mutated Docker")
			}
			origin, err := c.Store.PeerRecoveryExecutionScope(context.Background(), after.Identity.ExecutionID, "1")
			if err != nil || origin.EndpointIdentity != "engine-a" || origin.SessionEpoch != "1" {
				t.Fatal("origin rewritten", origin, err)
			}
		})
	}
}

func TestPeerRecoveryCoordinatorRepairsInterruptedCleanupWithoutSecondLaunch(t *testing.T) {
	for _, fault := range []string{"remove-reply", "event-reply", "authority-outage"} {
		t.Run(fault, func(t *testing.T) {
			c, r, remote, key := recoveryCoordinatorTest(t)
			a := approveRecoveryTest(t, c, remote, key, "cleanup")
			switch fault {
			case "remove-reply":
				r.loseRemove = true
			case "event-reply":
				remote.loseEventReply = true
			case "authority-outage":
				remote.deny = true
			}
			if err := c.Apply(context.Background(), a); err == nil {
				t.Fatal("fault unexpectedly completed")
			}
			if r.starts != 1 || r.creates != 1 {
				t.Fatal("fault relaunched workload")
			}
			remote.deny = false
			if err := c.Apply(context.Background(), a); err != nil {
				t.Fatal("safe retry failed", err)
			}
			if r.starts != 1 || r.creates != 1 || r.removes != 1 || remote.completionRequests != 1 {
				t.Fatal("retry repeated physical work", r.removes)
			}
		})
	}
}

func TestPeerRecoveryCoordinatorHoldsMissingContainersAndChangedPeer(t *testing.T) {
	for _, fault := range []string{"missing", "peer-restart", "host-reboot", "stale-snapshot", "hold"} {
		t.Run(fault, func(t *testing.T) {
			c, r, remote, key := recoveryCoordinatorTest(t)
			action := "cleanup"
			if fault == "missing" {
				r.object = nil
				action = "hold"
			}
			if fault == "hold" {
				action = "hold"
			}
			a := approveRecoveryTest(t, c, remote, key, action)
			switch fault {
			case "peer-restart":
				r.endpoint = "another-process"
			case "host-reboot":
				c.BootID = "a-different-actual-boot"
			case "stale-snapshot":
				if err := c.Store.InvalidateRuntime(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.Apply(context.Background(), a); err == nil {
				t.Fatal("ambiguous recovery completed")
			}
			native, err := c.Store.PeerRecoveryExecution(context.Background(), remote.start.Spec.ExecutionId, "1")
			if err != nil {
				t.Fatal(err)
			}
			if native.State == "cleaned" || remote.completionRequests != 0 || r.removes != 0 || r.starts != 1 || r.creates != 1 {
				t.Fatal("fence bypassed", native.State)
			}
		})
	}
}

func TestPeerRecoveryDiagnosticNeedsNoIdentityAndCannotBecomeApproval(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("production administrative recovery requires service UID")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := journal.OpenRecovery(context.Background(), dir, journal.Options{})
	if err != nil {
		t.Fatal(err)
	}
	storetest.Reconcile(t, store, storetest.Scope, "1")
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := AdministrativePeerRecovery(context.Background(), config.Config{StateDir: dir, RuntimeEndpoint: "unix:///nonexistent/runnerd-recovery-test.sock", CredentialFile: "/nonexistent/identity.json"}, "diagnose", "", "")
	if err != nil {
		t.Fatal("offline diagnostic required a credential", err)
	}
	var report map[string]any
	if json.Unmarshal(result, &report) != nil {
		t.Fatal("diagnostic JSON")
	}
	if report["domain"] != "neticora-runnerd-peer-recovery-diagnostic-v1" || report["inventoryComplete"] != false || report["admissionEnabled"] != false || report["mutationsEnabled"] != false {
		t.Fatal("diagnostic implied authority", report["runtimeStatus"])
	}
	if protocol.Validate("SignedPeerRecoveryPlan", result) == nil || protocol.Validate("SignedPeerRecoveryApproval", result) == nil {
		t.Fatal("unsigned diagnostic accepted as authority")
	}
	if _, err = os.Stat(filepath.Join(dir, "admission.drained")); err != nil {
		t.Fatal("diagnosis did not retain drain", err)
	}
}
