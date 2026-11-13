//go:build linux

package broker

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
)

type componentRetirement struct {
	*componentKata
	proof *katalinux.RetirementProof
}

func (k *componentRetirement) Retirement(context.Context, string, dockerengine.Plan) (*katalinux.RetirementProof, error) {
	return k.proof, nil
}
func TestKataRetirementAttestationBindsOriginalRemoval(t *testing.T) {
	e, _, base, k := isolatedFixture(t)
	_, _, _, issuer, _ := executionFixture(t, "PrepareImage")
	e.key = issuer.Public().(ed25519.PublicKey)
	e.boot = "12345678-1234-1234-1234-123456789abc"
	provider := &componentRetirement{componentKata: k}
	e.kata = provider
	resource := ""
	for revision, action := range []string{"PrepareImage", "CreateExecution", "StartExecution", "StopExecution", "RemoveExecution"} {
		r, s, c := physicalAuthorization(t, e, base, issuer, action, revision, resource)
		object, err := e.Execute(t.Context(), r, s, c)
		if err != nil {
			t.Fatal(err)
		}
		if action == "CreateExecution" {
			resource = object.ID
		}
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	e.handoffs = &handoffManager{ledger: e.ledger, root: root, boot: e.boot}
	p, err := e.settings.Plan(agent.StoreScope{InstallationID: e.scope.InstallationID, TenantID: e.scope.TenantID, HostID: e.scope.HostID, SessionEpoch: e.scope.SessionEpoch, EndpointIdentity: e.scope.EndpointIdentity}, base.Grant.Spec)
	if err != nil {
		t.Fatal(err)
	}
	records, err := e.ledger.records("handoffs")
	if err != nil {
		t.Fatal(err)
	}
	defer records.Close()
	if err = e.ledger.writeRecord(records, handoffID(p.Name), handoffRecord{Version: "runnerd-broker-handoff-v1", Name: p.Name, Boot: e.boot, Phase: "DISPOSED"}); err != nil {
		t.Fatal(err)
	}
	state, _, err := e.load(Lookup{ExecutionID: base.Grant.Binding.ExecutionID, Generation: base.Grant.Binding.Generation, SpecHash: base.Grant.Binding.SpecHash, ResourceID: resource})
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, op := range state.Operations {
		ids = append(ids, op.OperationID)
	}
	slices.Sort(ids)
	now := e.now()
	challenge := SignedDisposalChallenge{Challenge: DisposalChallenge{Version: DisposalVersion, Binding: state.Binding, ResourceID: resource, OperationIDs: ids, Nonce: strings.Repeat("a", 64), NotBefore: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), RetirementPolicy: katalinux.RetirementPolicy}}
	resign := func() {
		raw, _ := canonical(challenge.Challenge)
		challenge.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(issuer, append([]byte(DisposalChallengeDomain), raw...)))
	}
	resign()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Attest(t.Context(), challenge, private); err == nil {
		t.Fatal("missing retirement attested")
	}
	provider.proof = &katalinux.RetirementProof{Version: "runnerd09-retirement-v1", Policy: katalinux.RetirementPolicy, RecordHash: strings.Repeat("b", 64), OperationID: state.Operations["RemoveExecution"].OperationID}
	proof, err := e.Attest(t.Context(), challenge, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := canonical(proof.Disposal)
	signature, _ := base64.StdEncoding.DecodeString(proof.Signature)
	if !ed25519.Verify(public, append([]byte(DisposalDomain), raw...), signature) {
		t.Fatal("retirement outside signed disposal")
	}
	proof.Disposal.Retirement.RecordHash = strings.Repeat("c", 64)
	raw, _ = canonical(proof.Disposal)
	if ed25519.Verify(public, append([]byte(DisposalDomain), raw...), signature) {
		t.Fatal("retirement substitution unsigned")
	}
	provider.proof.OperationID = state.Operations["CreateExecution"].OperationID
	if _, err = e.Attest(t.Context(), challenge, private); err == nil {
		t.Fatal("different consumed operation gained disposal authority")
	}
	provider.proof.OperationID = state.Operations["RemoveExecution"].OperationID
	challenge.Challenge.RetirementPolicy = ""
	resign()
	if _, err = e.Attest(t.Context(), challenge, private); err == nil {
		t.Fatal("policy downgrade accepted")
	}
}
