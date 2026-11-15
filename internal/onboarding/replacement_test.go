package onboarding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

func unfinishedSetup(t *testing.T) (Options, *platform, attempt, []byte) {
	t.Helper()
	o, p := fixture(t)
	p.reject = true
	if _, err := Setup(context.Background(), p, o); err == nil {
		t.Fatal("initial enrollment unexpectedly succeeded")
	}
	var original attempt
	if err := readJSON(filepath.Join(o.SetupDir, "attempt.json"), &original); err != nil {
		t.Fatal(err)
	}
	seed, err := os.ReadFile(filepath.Join(o.SetupDir, "original-key.seed"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(seed) })
	return o, p, original, seed
}

func TestReplaceUnusedEnrollmentTokenPreservesIdentity(t *testing.T) {
	o, p, original, seed := unfinishedSetup(t)
	o.Token = func() ([]byte, error) { return []byte("fresh-replacement-secret"), nil }
	if _, err := Setup(context.Background(), p, o); err == nil {
		t.Fatal("replacement did not require explicit opt-in")
	}
	o.ReplaceToken = true
	p.reject = false
	if _, err := Setup(context.Background(), p, o); err != nil {
		t.Fatal(err)
	}
	var got protocol.EnrollmentRequest
	if err := json.Unmarshal(p.request, &got); err != nil {
		t.Fatal(err)
	}
	if got.RequestId != original.RequestID || got.Replacement == nil || got.Replacement.TenantId != original.TenantID || got.Replacement.RunnerDeploymentId != original.PoolID || len(got.Replacement.PriorTokenHashes) != 1 || got.Replacement.PriorTokenHashes[0] != original.TokenHash {
		t.Fatal("replacement changed original identity or authority bindings")
	}
	var after attempt
	_ = readJSON(filepath.Join(o.SetupDir, "attempt.json"), &after)
	afterSeed, _ := os.ReadFile(filepath.Join(o.SetupDir, "original-key.seed"))
	defer clear(afterSeed)
	if after != original || !bytes.Equal(seed, afterSeed) {
		t.Fatal("original attempt or key was overwritten")
	}
	if _, err := Setup(context.Background(), p, o); err == nil {
		t.Fatal("finished enrollment accepted replacement")
	}
}

func TestReplacementCrashAndLostResponse(t *testing.T) {
	for _, fault := range []string{"before-token-replacement", "after-token-replacement", "lost-response", "after-enrollment-response"} {
		t.Run(fault, func(t *testing.T) {
			o, p, _, _ := unfinishedSetup(t)
			o.ReplaceToken = true
			o.Token = func() ([]byte, error) { return []byte("fresh-replacement-secret"), nil }
			p.reject = false
			p.lost = fault == "lost-response"
			o.Checkpoint = func(point string) error {
				if point == fault {
					return errors.New("interrupted")
				}
				return nil
			}
			if _, err := Setup(context.Background(), p, o); err == nil {
				t.Fatal("fault did not interrupt replacement")
			}
			o.Checkpoint = nil
			if fault != "before-token-replacement" {
				o.ReplaceToken = false
			}
			if _, err := Setup(context.Background(), p, o); err != nil {
				t.Fatal(err)
			}
			if p.effects != 1 {
				t.Fatal("retry allocated replacement identity")
			}
		})
	}
}

func TestEarlierSuccessfulEnrollmentCanStillRecover(t *testing.T) {
	o, p := fixture(t)
	p.lost = true
	if _, err := Setup(context.Background(), p, o); err == nil {
		t.Fatal("response was not lost")
	}
	originalToken := o.Token
	o.ReplaceToken = true
	o.Token = func() ([]byte, error) { return []byte("fresh-replacement-secret"), nil }
	if _, err := Setup(context.Background(), p, o); err == nil {
		t.Fatal("replaced already committed enrollment")
	}
	o.ReplaceToken = false
	o.Token = originalToken
	if _, err := Setup(context.Background(), p, o); err != nil {
		t.Fatal(err)
	}
	if p.effects != 1 {
		t.Fatal("lost response caused duplicate identity")
	}
}

func TestMultipleUnusedReplacementsRetainAllFences(t *testing.T) {
	o, p, original, _ := unfinishedSetup(t)
	o.ReplaceToken = true
	o.Token = func() ([]byte, error) { return []byte("second-unused-secret"), nil }
	if _, err := Setup(context.Background(), p, o); err == nil {
		t.Fatal("rejection was not retained")
	}
	o.Token = func() ([]byte, error) { return []byte("third-unused-secret"), nil }
	p.reject = false
	if _, err := Setup(context.Background(), p, o); err != nil {
		t.Fatal(err)
	}
	var request protocol.EnrollmentRequest
	_ = json.Unmarshal(p.request, &request)
	if request.Replacement == nil || len(request.Replacement.PriorTokenHashes) != 2 || request.Replacement.PriorTokenHashes[0] != original.TokenHash || request.Replacement.PriorTokenHashes[1] != digest([]byte("second-unused-secret")) || request.RequestId != original.RequestID {
		t.Fatal("replacement omitted a predecessor or changed its original request")
	}
	for i := 1; i <= 2; i++ {
		if yes, err := exists(replacementPath(o, i)); err != nil || !yes {
			t.Fatal("candidate history was discarded")
		}
	}
}

func TestReplacementRejectsExistingOrCorruptState(t *testing.T) {
	for _, name := range []string{"credentials", "response", "journal", "history-gap", "history-key", "symlink"} {
		t.Run(name, func(t *testing.T) {
			o, p, original, _ := unfinishedSetup(t)
			o.ReplaceToken = true
			o.Token = func() ([]byte, error) { t.Fatal("unsafe state prompted for token"); return nil, nil }
			switch name {
			case "credentials":
				_ = Create(o.CredentialPath, []byte("{}"))
			case "response":
				_ = Create(filepath.Join(o.SetupDir, "enrollment.json"), []byte("{}"))
			case "journal":
				_ = Create(filepath.Join(o.StateDir, "journal.sqlite"), []byte("original-runtime-state"))
			default:
				o.Token = func() ([]byte, error) { return []byte("fresh-replacement-secret"), nil }
				r := tokenReplacement{RequestID: original.RequestID, Fingerprint: original.Fingerprint, PreviousTokenHash: original.TokenHash, TokenHash: digest([]byte("second-unused-secret"))}
				index := 1
				if name == "history-gap" {
					index = 2
				}
				if name == "history-key" {
					r.Fingerprint = "other-key"
				}
				if name == "symlink" {
					_ = os.Symlink(filepath.Join(o.SetupDir, "attempt.json"), replacementPath(o, index))
				} else {
					_ = saveJSON(replacementPath(o, index), r)
				}
			}
			p.reject = false
			if _, err := Setup(context.Background(), p, o); err == nil {
				t.Fatal("unsafe replacement state was accepted")
			}
			if p.calls != 0 {
				t.Fatal("unsafe state contacted platform")
			}
		})
	}
}

func TestOrdinaryRetryCannotBypassReplacementRuntimeGuard(t *testing.T) {
	o, p, _, _ := unfinishedSetup(t)
	o.ReplaceToken = true
	o.Token = func() ([]byte, error) { return []byte("fresh-replacement-secret"), nil }
	if _, err := Setup(context.Background(), p, o); err == nil {
		t.Fatal("expected rejected replacement")
	}
	if err := Create(filepath.Join(o.StateDir, "journal.sqlite"), []byte("runtime-history")); err != nil {
		t.Fatal(err)
	}
	o.ReplaceToken = false
	p.reject = false
	if _, err := Setup(context.Background(), p, o); err == nil {
		t.Fatal("ordinary retry bypassed runtime guard")
	}
	if p.calls != 0 {
		t.Fatal("runtime conflict contacted platform")
	}
}

func TestReplacementHistoryBound(t *testing.T) {
	o, p, original, _ := unfinishedSetup(t)
	previous := original.TokenHash
	for i := 1; i <= maxTokenReplacements; i++ {
		next := digest([]byte(fmt.Sprintf("replacement-%d", i)))
		if err := saveJSON(replacementPath(o, i), tokenReplacement{RequestID: original.RequestID, Fingerprint: original.Fingerprint, PreviousTokenHash: previous, TokenHash: next}); err != nil {
			t.Fatal(err)
		}
		previous = next
	}
	o.ReplaceToken = true
	o.Token = func() ([]byte, error) { return []byte("one-too-many-replacements"), nil }
	p.reject = false
	if _, err := Setup(context.Background(), p, o); err == nil {
		t.Fatal("unbounded replacement history")
	}
	if p.calls != 0 {
		t.Fatal("history bound contacted platform")
	}
}

func TestRecoveryIncludesCandidatesRecordedAfterLostSuccess(t *testing.T) {
	o, p, original, _ := unfinishedSetup(t)
	o.ReplaceToken = true
	o.Token = func() ([]byte, error) { return []byte("successful-candidate-secret"), nil }
	p.reject = false
	p.lost = true
	if _, err := Setup(context.Background(), p, o); err == nil {
		t.Fatal("response was not lost")
	}
	o.Token = func() ([]byte, error) { return []byte("later-failed-candidate-secret"), nil }
	if _, err := Setup(context.Background(), p, o); err == nil {
		t.Fatal("later candidate replaced original registration")
	}
	o.ReplaceToken = false
	o.Token = func() ([]byte, error) { return []byte("successful-candidate-secret"), nil }
	if _, err := Setup(context.Background(), p, o); err != nil {
		t.Fatal(err)
	}
	var request protocol.EnrollmentRequest
	if json.Unmarshal(p.lastRequest, &request) != nil || request.Replacement == nil {
		t.Fatal("missing recovery history")
	}
	hashes := request.Replacement.PriorTokenHashes
	if len(hashes) != 2 || hashes[0] != original.TokenHash || hashes[1] != digest([]byte("later-failed-candidate-secret")) {
		t.Fatal("recovery omitted a later failed candidate")
	}
	if p.effects != 1 {
		t.Fatal("response recovery allocated another identity")
	}
}
