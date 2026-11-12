//go:build linux

package broker

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBrokerOriginatedChallengeSurvivesRestartAndConsumesOnce(t *testing.T) {
	l, path := testLedger(t)
	r, s, key, private, now := executionFixture(t, "PrepareImage")
	if _, err := l.IssueChallenge(r, now); err == nil {
		t.Fatal("caller-chosen challenge accepted")
	}
	r.Challenge = ""
	c, err := l.IssueChallenge(r, now)
	if err != nil {
		t.Fatal(err)
	}
	again, err := l.IssueChallenge(r, now)
	if err != nil || c != again {
		t.Fatal("outstanding challenge replaced")
	}
	if !digest(c.Request.Challenge) || c.Request.Challenge == strings.Repeat("0", 64) {
		t.Fatal("challenge not random")
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	again, err = l.IssueChallenge(r, now)
	if err != nil || c != again {
		t.Fatal("challenge lost on restart")
	}
	r = c.Request
	s.Grant.Challenge = r.Challenge
	signExecution(t, &s, private)
	commit := testCommit(t, s, private, now)
	var wg sync.WaitGroup
	first := make(chan bool, 8)
	for range 8 {
		wg.Go(func() {
			_, duplicate, err := l.AcceptExecutionIntent(s, r, key, testBinding(), now, commit)
			if err != nil {
				t.Error(err)
			}
			first <- !duplicate
		})
	}
	wg.Wait()
	close(first)
	n := 0
	for original := range first {
		if original {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d consumed intents", n)
	}
	copy := r
	copy.Challenge = ""
	if _, err = l.IssueChallenge(copy, now); err == nil {
		t.Fatal("consumed challenge reopened")
	}
}

func TestChallengeConsumptionSurvivesSIGKILLBeforeIntentReceipt(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestBrokerIntentCrashHelper$")
	command.Env = append(os.Environ(), "NETICORA_BROKER_TEST_CRASH_PATH="+path, "NETICORA_BROKER_TEST_CONSUME_ONLY=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	ready := make(chan bool, 1)
	go func() {
		line, err := bufio.NewReader(stdout).ReadString('\n')
		ready <- err == nil && line == "challenge-durable\n"
	}()
	select {
	case ok := <-ready:
		if !ok {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatal("child did not consume challenge")
		}
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("child barrier timed out")
	}
	if err = command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if command.Wait() == nil {
		t.Fatal("child survived kill")
	}
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	r, _, _, _, now := executionFixture(t, "PrepareImage")
	r.Challenge = ""
	if _, err = l.IssueChallenge(r, now); err == nil {
		t.Fatal("crash reopened consumed authorization")
	}
	root, err := l.records("challenges")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var c Challenge
	if err = readRecord(root, r.OperationID, &c); err != nil {
		t.Fatal(err)
	}
	if c.State != "CONSUMED" || c.Binding == nil || !c.Binding.valid() || !digest(c.GrantHash) {
		t.Fatal("crash lost original authority binding")
	}
	if _, err = l.Get(r.OperationID); !os.IsNotExist(err) {
		t.Fatal("test did not exercise pre-receipt crash boundary", err)
	}
}

func TestChallengeRejectsMissingCommitExpiredOrSubstitutedAuthorization(t *testing.T) {
	for _, scenario := range []string{"missing-commit", "wrong-challenge", "expired", "bad-commit-signature", "different-operation", "extended-expiry"} {
		t.Run(scenario, func(t *testing.T) {
			l, _ := testLedger(t)
			r, s, key, private, now := executionFixture(t, "PrepareImage")
			commit := freshChallenge(t, l, &r, &s, private, now)
			switch scenario {
			case "missing-commit":
				if _, _, err := l.AcceptExecutionIntent(s, r, key, testBinding(), now); err == nil {
					t.Fatal("grant alone accepted")
				}
				return
			case "wrong-challenge":
				r.Challenge = strings.Repeat("e", 64)
				s.Grant.Challenge = r.Challenge
				signExecution(t, &s, private)
				commit = testCommit(t, s, private, now)
			case "expired":
				now = now.Add(16 * time.Second)
			case "bad-commit-signature":
				commit.Signature = strings.Repeat("A", 86) + "=="
			case "different-operation":
				commit.Commit.OperationID = strings.Repeat("e", 64)
			case "extended-expiry":
				commit.Commit.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339Nano)
			}
			if _, _, err := l.AcceptExecutionIntent(s, r, key, testBinding(), now, commit); err == nil {
				t.Fatal("invalid freshness accepted")
			}
			if _, err := l.Get(r.OperationID); err == nil {
				t.Fatal("invalid challenge minted durable intent/fence")
			}
		})
	}
}

func TestExpiredChallengeCannotMatchRenewedCycle(t *testing.T) {
	l, _ := testLedger(t)
	r, s, key, private, now := executionFixture(t, "PrepareImage")
	freshChallenge(t, l, &r, &s, private, now)
	oldRequest, oldGrant := r, s
	r.Challenge = ""
	newTime := now.Add(16 * time.Second)
	next, err := l.IssueChallenge(r, newTime)
	if err != nil {
		t.Fatal(err)
	}
	if next.Request.Challenge == oldRequest.Challenge {
		t.Fatal("challenge reused")
	}
	oldGrant.Grant.NotBefore = newTime.Format(time.RFC3339Nano)
	oldGrant.Grant.ExpiresAt = newTime.Add(time.Second).Format(time.RFC3339Nano)
	signExecution(t, &oldGrant, private)
	commit := testCommit(t, oldGrant, private, newTime)
	if _, _, err = l.AcceptExecutionIntent(oldGrant, oldRequest, key, testBinding(), newTime, commit); err == nil {
		t.Fatal("old nonce matched new cycle")
	}
}
