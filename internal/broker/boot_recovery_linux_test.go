//go:build linux

package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

const bootBefore = "12345678-1234-1234-1234-123456789abc"
const bootAfter = "87654321-4321-4321-4321-cba987654321"

func bootFixture(t *testing.T, present bool) (*physicalExecutor, *componentRuntime, Lookup, ed25519.PrivateKey, ed25519.PrivateKey, map[string][]byte) {
	t.Helper()
	e, runtime, base, issuer, _ := physicalFixture(t)
	e.boot = bootBefore
	q := Lookup{ExecutionID: base.Grant.Binding.ExecutionID, Generation: base.Grant.Binding.Generation, SpecHash: base.Grant.Binding.SpecHash}
	for revision, action := range []string{"PrepareImage", "CreateExecution"} {
		r, s, c := physicalAuthorization(t, e, base, issuer, action, revision, "")
		if !present && action == "CreateExecution" {
			e.checkpoint = func(point string, _ ExecutionGrantRequest) error {
				if point == "before-effect" {
					return dockerengine.ErrUnavailable
				}
				return nil
			}
		}
		_, err := e.Execute(context.Background(), r, s, c)
		if present && err != nil {
			t.Fatal(err)
		}
	}
	e.checkpoint = nil
	state, p, err := e.load(q)
	if err != nil {
		t.Fatal(err)
	}
	root, err := e.ledger.records("handoffs")
	if err != nil {
		t.Fatal(err)
	}
	err = e.ledger.writeRecord(root, handoffID(p.Name), handoffRecord{Version: "runnerd-broker-handoff-v1", Name: p.Name, Boot: bootBefore, Device: 1, Inode: 2, Hash: state.Spec.SpecHash, Phase: "READY"})
	root.Close()
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
	handoff, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { handoff.Close() })
	e.boot = bootAfter
	e.handoffs = &handoffManager{ledger: e.ledger, root: handoff, boot: bootAfter}
	_, disposal, _ := ed25519.GenerateKey(rand.Reader)
	return e, runtime, q, issuer, disposal, original
}
func bootAuthority(t *testing.T, e *physicalExecutor, q Lookup, issuer, disposal ed25519.PrivateKey) SignedBootCertificate {
	t.Helper()
	ch, err := e.IssueBootChallenge(context.Background(), q, disposal)
	if err != nil {
		t.Fatal(err)
	}
	c := BootCertificate{Version: BootRecoveryVersion, Operation: "RecoverBootCleanup", ID: bootHash(ch), Challenge: ch, NotBefore: e.now().UTC().Format(time.RFC3339Nano), ExpiresAt: ch.Challenge.ExpiresAt}
	return SignedBootCertificate{Certificate: c, Signature: signBoot(BootRecoveryDomain, c, issuer)}
}
func unchangedBootOriginals(t *testing.T, original map[string][]byte) {
	t.Helper()
	for path, raw := range original {
		now, err := os.ReadFile(path)
		if err != nil || string(now) != string(raw) {
			t.Fatalf("original ownership altered: %s %v", path, err)
		}
	}
}
func TestBootRecoveryAbsentUnknownCreatePreservesOriginalObligation(t *testing.T) {
	e, runtime, q, issuer, disposal, original := bootFixture(t, false)
	if _, err := e.State(context.Background(), q, true); !errors.Is(err, ErrBootRecovery) {
		t.Fatal(err)
	}
	a := bootAuthority(t, e, q, issuer, disposal)
	if err := e.RecoverBoot(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	state, err := e.State(context.Background(), q, true)
	if !errors.Is(err, dockerengine.ErrAbsent) || state.Phase != "RECOVERY_DISPOSED" || state.RecoveryID != a.Certificate.ID {
		t.Fatal(state, err)
	}
	if runtime.creates != 0 || runtime.starts != 0 || runtime.removes != 0 {
		t.Fatal("unknown create repeated")
	}
	unchangedBootOriginals(t, original)
	ch := DisposalChallenge{Version: DisposalVersion, Binding: a.Certificate.Challenge.Challenge.Binding, OperationIDs: a.Certificate.Challenge.Challenge.OperationIDs, Nonce: a.Certificate.Challenge.Challenge.Nonce, NotBefore: a.Certificate.NotBefore, ExpiresAt: a.Certificate.ExpiresAt, RecoveryID: a.Certificate.ID}
	signed := SignedDisposalChallenge{Challenge: ch, Signature: signBoot(DisposalChallengeDomain, ch, issuer)}
	proof, err := e.Attest(context.Background(), signed, disposal)
	if err != nil || proof.Disposal.State != "RECOVERY_DISPOSED" || proof.Disposal.RecoveryID != a.Certificate.ID {
		t.Fatal(proof, err)
	}
	now := e.now().Add(time.Minute)
	e.now = func() time.Time { return now }
	if err = e.RecoverBoot(context.Background(), a); err != nil {
		t.Fatal("idempotent original cleanup expired", err)
	}
	if _, err = e.Attest(context.Background(), signed, disposal); err == nil {
		t.Fatal("stale disposal proof accepted")
	}
	unchangedBootOriginals(t, original)
}
func TestBootRecoveryPresentOriginalAndLostRemove(t *testing.T) {
	e, runtime, q, issuer, disposal, original := bootFixture(t, true)
	for id, o := range runtime.objects {
		o.State = "running"
		runtime.objects[id] = o
	}
	a := bootAuthority(t, e, q, issuer, disposal)
	runtime.lostRemove = true
	if err := e.RecoverBoot(context.Background(), a); err == nil {
		t.Fatal("lost removal acknowledged")
	}
	now := e.now().Add(time.Minute)
	e.now = func() time.Time { return now }
	recovered, err := e.IssueBootChallenge(context.Background(), q, disposal)
	if err != nil || bootHash(recovered) != bootHash(a.Certificate.Challenge) {
		t.Fatal("original accepted authority replaced", err)
	}
	if err = e.RecoverBoot(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if runtime.creates != 1 || runtime.starts != 0 || runtime.stops != 1 || runtime.removes != 1 {
		t.Fatal("effect repeated", runtime)
	}
	unchangedBootOriginals(t, original)
}
func TestBootRecoveryRejectsForgedSubstitutionAndChangedEngine(t *testing.T) {
	for _, name := range []string{"signature", "domain", "boot", "state", "target", "nonce", "expired", "engine", "replacement", "handoff", "receipt"} {
		t.Run(name, func(t *testing.T) {
			e, runtime, q, issuer, disposal, original := bootFixture(t, true)
			a := bootAuthority(t, e, q, issuer, disposal)
			switch name {
			case "signature":
				a.Signature = "forged"
			case "domain":
				a.Certificate.Operation = "CreateExecution"
			case "boot":
				a.Certificate.Challenge.Challenge.ToBoot = bootBefore
			case "state":
				a.Certificate.Challenge.Challenge.StateHash = string(make([]byte, 64))
			case "target":
				a.Certificate.Challenge.Challenge.TargetID = ""
			case "nonce":
				a.Certificate.Challenge.Challenge.Nonce = ""
			case "expired":
				now := e.now().Add(time.Minute)
				e.now = func() time.Time { return now }
			case "engine":
				runtime.peerChanged = true
			case "replacement":
				s, p, _ := e.loadOriginal(q)
				runtime.names[p.Name] = agentID()
				runtime.objects[agentID()] = dockerengine.Object{ID: agentID(), State: "prepared"}
				_ = s
			case "handoff":
				s, p, _ := e.loadOriginal(q)
				_ = s
				e.handoffs.root.Mkdir(p.Name, 0700)
			case "receipt":
				for path := range original {
					if filepath.Dir(path) == e.ledger.root.Name() && filepath.Ext(path) == ".json" {
						os.Remove(path)
						break
					}
				}
			}
			if name != "signature" && name != "expired" && name != "engine" && name != "replacement" && name != "handoff" && name != "receipt" {
				a.Certificate.ID = bootHash(a.Certificate.Challenge)
				a.Signature = signBoot(BootRecoveryDomain, a.Certificate, issuer)
			}
			if err := e.RecoverBoot(context.Background(), a); err == nil {
				t.Fatal("invalid authority completed")
			}
			if name != "handoff" && (runtime.stops != 0 || runtime.removes != 0) {
				t.Fatal("invalid authority mutated Docker")
			}
		})
	}
}
func agentID() string { return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }

func TestBootRecoverySecondBootRequiresChainedOriginalAuthority(t *testing.T) {
	e, runtime, q, issuer, disposal, original := bootFixture(t, true)
	first := bootAuthority(t, e, q, issuer, disposal)
	runtime.lostRemove = true
	if err := e.RecoverBoot(context.Background(), first); err == nil {
		t.Fatal("lost response expected")
	}
	e.boot = "abcdefab-abcd-abcd-abcd-abcdefabcdef"
	e.handoffs.boot = e.boot
	now := e.now().Add(time.Minute)
	e.now = func() time.Time { return now }
	if _, err := e.State(context.Background(), q, true); !errors.Is(err, ErrBootRecovery) {
		t.Fatal("new boot adopted without authority", err)
	}
	if err := e.RecoverBoot(context.Background(), first); err == nil {
		t.Fatal("old boot authority reused")
	}
	second := bootAuthority(t, e, q, issuer, disposal)
	if second.Certificate.Challenge.Challenge.PreviousRecoveryID != first.Certificate.ID || second.Certificate.Challenge.Challenge.TargetID != first.Certificate.Challenge.Challenge.TargetID {
		t.Fatal("original recovery ownership lost")
	}
	if err := e.RecoverBoot(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if runtime.creates != 1 || runtime.removes != 1 {
		t.Fatal("original effect repeated")
	}
	unchangedBootOriginals(t, original)
	root, err := e.ledger.records("boot-history")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var prior bootRecord
	if err = readRecord(root, first.Certificate.ID, &prior); err != nil || bootHash(prior.Authority) != bootHash(first) {
		t.Fatal("prior authority lost", err)
	}
	root.Remove(first.Certificate.ID + ".json")
	if _, err = e.State(context.Background(), q, true); err == nil || errors.Is(err, dockerengine.ErrAbsent) {
		t.Fatal("missing history permitted disposal", err)
	}
}

func TestBootRecoveryLegacyUnanchoredRecordRemainsQuarantined(t *testing.T) {
	e, runtime, q, _, disposal, _ := bootFixture(t, false)
	s, _, err := e.loadOriginal(q)
	if err != nil {
		t.Fatal(err)
	}
	s.EngineAnchor = ""
	root, err := e.ledger.records("resources")
	if err != nil {
		t.Fatal(err)
	}
	err = e.ledger.writeRecord(root, recordID(s.Binding), s)
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.IssueBootChallenge(context.Background(), q, disposal); err == nil {
		t.Fatal("invented retrospective storage anchor")
	}
	if runtime.creates != 0 || runtime.stops != 0 || runtime.removes != 0 {
		t.Fatal("legacy ownership changed")
	}
}
func TestBootRecoveryNetworkAmbiguityRetainsOriginalPendingIntent(t *testing.T) {
	e, runtime, q, issuer, disposal, original := bootFixture(t, false)
	a := bootAuthority(t, e, q, issuer, disposal)
	runtime.networkAttached = true
	if err := e.RecoverBoot(context.Background(), a); err == nil {
		t.Fatal("uncertain network disposed")
	}
	s, _, _ := e.loadOriginal(q)
	record, err := e.bootRecord(s)
	if err != nil || record.Phase != "PENDING" {
		t.Fatal(record, err)
	}
	runtime.networkAttached = false
	if err = e.RecoverBoot(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if runtime.creates != 0 || runtime.starts != 0 || runtime.removes != 0 {
		t.Fatal("replacement effect issued")
	}
	unchangedBootOriginals(t, original)
}
