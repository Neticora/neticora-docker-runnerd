//go:build linux

package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

func TestLostCreateReconcilesOriginalWithoutRenewedAuthority(t *testing.T) {
	e, runtime, base, key, now := physicalFixture(t)
	runtime.lostCreate = true
	r, s, c := physicalAuthorization(t, e, base, key, "CreateExecution", 0, "")
	if _, err := e.Execute(context.Background(), r, s, c); !errors.Is(err, ErrQuarantined) {
		t.Fatal(err)
	}
	e.now = func() time.Time { return now.Add(time.Minute) }
	q := Lookup{ExecutionID: r.ExecutionID, Generation: r.Generation, SpecHash: base.Grant.Binding.SpecHash}
	state, err := e.State(context.Background(), q, true)
	if err != nil || state.Phase != "PREPARED" || state.Revision != "1" || state.Object == nil || state.Operations["CreateExecution"].OperationID != r.OperationID || runtime.creates != 1 {
		t.Fatalf("original not reconciled: %+v %v", state, err)
	}
	if _, err = e.Execute(context.Background(), r, s, c); err == nil {
		t.Fatal("expired authority executed")
	}
	if runtime.creates != 1 {
		t.Fatal("replacement created")
	}
}

func TestUnstartedDisposalFencesFutureLaunch(t *testing.T) {
	e, runtime, base, key, _ := physicalFixture(t)
	r, s, c := physicalAuthorization(t, e, base, key, "PrepareImage", 0, "")
	if _, err := e.Execute(context.Background(), r, s, c); err != nil {
		t.Fatal(err)
	}
	r, s, c = physicalAuthorization(t, e, base, key, "DisposeUnstarted", 1, "")
	if _, err := e.Execute(context.Background(), r, s, c); err != nil {
		t.Fatal(err)
	}
	state, err := e.State(context.Background(), Lookup{ExecutionID: r.ExecutionID, Generation: r.Generation, SpecHash: base.Grant.Binding.SpecHash}, true)
	if !errors.Is(err, dockerengine.ErrAbsent) || state.Phase != "NEVER_CREATED" || runtime.creates != 0 {
		t.Fatal(state, err)
	}
	r, s, c = physicalAuthorization(t, e, base, key, "CreateExecution", 2, "")
	if _, err = e.Execute(context.Background(), r, s, c); err == nil {
		t.Fatal("cleanup grant reopened launch")
	}
}

func TestFreshDisposalRequiresExactCommitmentsAndHandoffAbsence(t *testing.T) {
	e, runtime, base, issuer, now := physicalFixture(t)
	e.boot = "12345678-1234-1234-1234-123456789abc"
	resource := ""
	for revision, action := range []string{"PrepareImage", "CreateExecution", "StartExecution", "StopExecution", "RemoveExecution"} {
		r, s, c := physicalAuthorization(t, e, base, issuer, action, revision, resource)
		o, err := e.Execute(context.Background(), r, s, c)
		if err != nil {
			t.Fatal(err)
		}
		if action == "CreateExecution" {
			resource = o.ID
		}
	}
	// Component-only disposed handoff fixture. Live construction additionally
	// requires protected tmpfs, ownership and mount guards.
	target := t.TempDir()
	root, err := os.OpenRoot(target)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	e.handoffs = &handoffManager{ledger: e.ledger, root: root, boot: e.boot}
	p, err := e.settings.Plan(agent.StoreScope{InstallationID: e.scope.InstallationID, TenantID: e.scope.TenantID, HostID: e.scope.HostID, SessionEpoch: e.scope.SessionEpoch, EndpointIdentity: e.scope.EndpointIdentity}, base.Grant.Spec)
	if err != nil {
		t.Fatal(err)
	}
	hr, err := e.ledger.records("handoffs")
	if err != nil {
		t.Fatal(err)
	}
	defer hr.Close()
	if err = e.ledger.writeRecord(hr, handoffID(p.Name), handoffRecord{Version: "runnerd-broker-handoff-v1", Name: p.Name, Boot: e.boot, Phase: "DISPOSED"}); err != nil {
		t.Fatal(err)
	}
	state, err := e.State(context.Background(), Lookup{ExecutionID: base.Grant.Binding.ExecutionID, Generation: base.Grant.Binding.Generation, SpecHash: base.Grant.Binding.SpecHash}, false)
	if !errors.Is(err, dockerengine.ErrAbsent) {
		t.Fatal(err)
	}
	ids := []string{}
	for _, r := range state.Operations {
		ids = append(ids, r.OperationID)
	}
	slices.Sort(ids)
	challenge := SignedDisposalChallenge{Challenge: DisposalChallenge{Version: DisposalVersion, Binding: base.Grant.Binding, ResourceID: resource, OperationIDs: ids, Nonce: strings.Repeat("d", 64), NotBefore: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}}
	resign := func() {
		raw, _ := canonical(challenge.Challenge)
		challenge.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(issuer, append([]byte(DisposalChallengeDomain), raw...)))
	}
	resign()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	proof, err := e.Attest(context.Background(), challenge, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := canonical(proof.Disposal)
	signature, _ := base64.StdEncoding.DecodeString(proof.Signature)
	if !ed25519.Verify(public, append([]byte(DisposalDomain), raw...), signature) || proof.Disposal.ResourceID != resource || proof.Disposal.State != "REMOVED" {
		t.Fatal("invalid disposal proof")
	}
	challenge.Challenge.OperationIDs = ids[:len(ids)-1]
	resign()
	if _, err = e.Attest(context.Background(), challenge, private); err == nil {
		t.Fatal("incomplete commitment set accepted")
	}
	challenge.Challenge.OperationIDs = ids
	resign()
	runtime.networkAttached = true
	if _, err = e.Attest(context.Background(), challenge, private); err == nil {
		t.Fatal("attached network attested absent")
	}
	runtime.networkAttached = false
	if err = root.Mkdir(p.Name, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Attest(context.Background(), challenge, private); err == nil {
		t.Fatal("reappearing handoff attested absent")
	}
	if err = root.Remove(p.Name); err != nil {
		t.Fatal(err)
	}
	e.now = func() time.Time { return now.Add(time.Minute) }
	if _, err = e.Attest(context.Background(), challenge, private); err == nil {
		t.Fatal("expired challenge accepted")
	}
}

func TestShippingBuildRejectsConfiguredDockerBackend(t *testing.T) {
	if runtimeQualification {
		t.Skip("qualification build explicitly selected")
	}
	if _, _, close, err := openRuntime(context.Background(), Config{Runtime: &RuntimeConfig{}}, nil, nil); err == nil {
		close()
		t.Fatal("shipping runtime activated")
	}
}
