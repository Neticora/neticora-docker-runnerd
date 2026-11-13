//go:build linux

package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

type recoveryKataFixture struct {
	*componentKata
	uncertain, interrupted bool
}

func (*recoveryKataFixture) Origin() (json.RawMessage, error) {
	return json.RawMessage(`{"original":"immutable-kata-pool"}`), nil
}
func (k *recoveryKataFixture) Observe(context.Context, string, dockerengine.Plan) error {
	if k.uncertain {
		return ErrQuarantined
	}
	return nil
}
func (k *recoveryKataFixture) Absence(ctx context.Context, id string, p dockerengine.Plan) error {
	if err := k.Observe(ctx, id, p); err != nil {
		return err
	}
	return k.componentKata.Absence(ctx, id, p)
}
func (k *recoveryKataFixture) Evidence(ctx context.Context, id string, p dockerengine.Plan) (json.RawMessage, error) {
	if err := k.Absence(ctx, id, p); err != nil {
		return nil, err
	}
	return json.RawMessage(`{"original":"disposed"}`), nil
}
func (k *recoveryKataFixture) RecoverDispose(ctx context.Context, id string, p dockerengine.Plan, guard func() error) error {
	if err := k.Observe(ctx, id, p); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if k.interrupted {
		return dockerengine.ErrUnavailable
	}
	return k.Dispose(ctx, id, p, "", guard)
}
func kataBootFixture(t *testing.T) (*physicalExecutor, *componentRuntime, *recoveryKataFixture, Lookup, ed25519.PrivateKey, ed25519.PrivateKey, map[string][]byte) {
	t.Helper()
	e, r, s, k := isolatedFixture(t)
	_, _, _, issuer, _ := executionFixture(t, "PrepareImage")
	e.key = issuer.Public().(ed25519.PublicKey)
	e.boot = bootBefore
	recovery := &recoveryKataFixture{componentKata: k}
	e.kata = recovery
	origin, _ := recovery.Origin()
	e.restoreKata = func(raw json.RawMessage) (kataBootLifecycle, error) {
		if string(raw) != string(origin) {
			return nil, ErrQuarantined
		}
		return recovery, nil
	}
	q := Lookup{ExecutionID: s.Grant.Binding.ExecutionID, Generation: s.Grant.Binding.Generation, SpecHash: s.Grant.Binding.SpecHash}
	for revision, action := range []string{"PrepareImage", "CreateExecution", "StartExecution"} {
		request, grant, commit := physicalAuthorization(t, e, s, issuer, action, revision, q.ResourceID)
		object, err := e.Execute(context.Background(), request, grant, commit)
		if err != nil {
			t.Fatal(err)
		}
		if action == "CreateExecution" {
			q.ResourceID = object.ID
		}
	}
	state, plan, err := e.load(q)
	if err != nil {
		t.Fatal(err)
	}
	handoffs, err := e.ledger.records("handoffs")
	if err != nil {
		t.Fatal(err)
	}
	err = e.ledger.writeRecord(handoffs, handoffID(plan.Name), handoffRecord{Version: "runnerd-broker-handoff-v1", Name: plan.Name, Boot: bootBefore, Device: 1, Inode: 2, Hash: state.Spec.SpecHash, Phase: "READY"})
	handoffs.Close()
	if err != nil {
		t.Fatal(err)
	}
	original := map[string][]byte{}
	filepath.WalkDir(e.ledger.root.Name(), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !entry.IsDir() && entry.Name() != "instance.lock" {
			original[path], err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
		}
		return nil
	})
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	e.boot = bootAfter
	e.handoffs = &handoffManager{ledger: e.ledger, root: root, boot: bootAfter}
	_, disposal, _ := ed25519.GenerateKey(rand.Reader)
	return e, r, recovery, q, issuer, disposal, original
}
func TestKataBootCleanupRetainsOriginalAcrossInterruptedBoots(t *testing.T) {
	e, r, k, q, issuer, disposal, original := kataBootFixture(t)
	first := bootAuthority(t, e, q, issuer, disposal)
	if first.Certificate.Challenge.Challenge.KataAnchor == "" {
		t.Fatal("unbound Kata authority")
	}
	k.interrupted = true
	if err := e.RecoverBoot(context.Background(), first); err == nil {
		t.Fatal("interrupted storage cleanup completed")
	}
	state, _, err := e.loadOriginal(q)
	if err != nil {
		t.Fatal(err)
	}
	record, err := e.bootRecord(state)
	if err != nil || record.Phase != "PENDING" {
		t.Fatal(record, err)
	}
	if _, err = e.State(context.Background(), q, true); !errors.Is(err, ErrBootRecovery) {
		t.Fatal("uncertain storage released", err)
	}
	e.boot = "abcdefab-abcd-abcd-abcd-abcdefabcdef"
	e.handoffs.boot = e.boot
	if err = e.RecoverBoot(context.Background(), first); err == nil {
		t.Fatal("prior boot reused")
	}
	second := bootAuthority(t, e, q, issuer, disposal)
	if second.Certificate.Challenge.Challenge.PreviousRecoveryID != first.Certificate.ID {
		t.Fatal("lost original chain")
	}
	if _, err = e.kataEvidence(context.Background(), q); err == nil {
		t.Fatal("pending recovery exported disposal")
	}
	k.interrupted = false
	if err = e.RecoverBoot(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	result, err := e.State(context.Background(), q, true)
	if !errors.Is(err, dockerengine.ErrAbsent) || result.Phase != "RECOVERY_DISPOSED" {
		t.Fatal(result, err)
	}
	if r.creates != 1 || r.starts != 1 || r.stops != 1 || r.removes != 1 || k.prepare != 1 || k.disposals != 1 {
		t.Fatal("replaced/repeated original effect", r, k)
	}
	if raw, err := e.kataEvidence(context.Background(), q); err != nil || len(raw) == 0 {
		t.Fatal("original recovery evidence unavailable", err)
	}
	k.uncertain = true
	if _, err = e.kataEvidence(context.Background(), q); err == nil {
		t.Fatal("uncertain recovery exported disposal")
	}
	if _, err = e.State(context.Background(), q, true); err == nil {
		t.Fatal("storage continuity loss ignored")
	}
	unchangedBootOriginals(t, original)
}
func TestKataBootRejectsMissingOriginAndSubstitutedAuthority(t *testing.T) {
	for _, name := range []string{"anchor", "docker-only", "launch", "ownership", "legacy", "unknown-create"} {
		t.Run(name, func(t *testing.T) {
			e, r, k, q, issuer, disposal, _ := kataBootFixture(t)
			a := bootAuthority(t, e, q, issuer, disposal)
			switch name {
			case "anchor":
				a.Certificate.Challenge.Challenge.KataAnchor = agentID()
			case "docker-only":
				a.Certificate.Challenge.Challenge.KataAnchor = ""
			case "launch":
				a.Certificate.Operation = "StartExecution"
			case "ownership":
				k.uncertain = true
			case "legacy", "unknown-create":
				state, _, err := e.loadOriginal(q)
				if err != nil {
					t.Fatal(err)
				}
				if name == "legacy" {
					state.KataOrigin = nil
				} else {
					state.ResourceID = ""
				}
				root, _ := e.ledger.records("resources")
				err = e.ledger.writeRecord(root, recordID(state.Binding), state)
				root.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			a.Certificate.ID = bootHash(a.Certificate.Challenge)
			a.Signature = signBoot(BootRecoveryDomain, a.Certificate, issuer)
			if err := e.RecoverBoot(context.Background(), a); err == nil {
				t.Fatal("unsafe recovery accepted")
			}
			if r.stops+r.removes != 0 || r.creates != 1 || r.starts != 1 {
				t.Fatal("invalid recovery mutated runtime")
			}
		})
	}
}
