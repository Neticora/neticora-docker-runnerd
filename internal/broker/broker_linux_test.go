//go:build linux

package broker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testBinding() Binding {
	return Binding{InstallationID: "installation", TenantID: "tenant", HostID: "host", SessionEpoch: "3", EndpointIdentity: "docker-original", ExecutionID: "execution", Generation: "2", AttemptID: "attempt", SpecHash: strings.Repeat("a", 64)}
}

func testLedger(t *testing.T) (*Ledger, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	l, err := OpenLedger(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, directory
}

func signedRequest(t *testing.T) (Request, ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	r := Request{Version: Version, Operation: "GetOperationStatus", Target: strings.Repeat("b", 64), Authorization: &SignedGrant{Grant: Grant{Version: Version, Audience: "broker-installation", Operation: "GetOperationStatus", Target: strings.Repeat("b", 64), Binding: testBinding(), NotBefore: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano)}}}
	resign(t, &r, private)
	return r, public, private, now
}

func resign(t *testing.T, r *Request, key ed25519.PrivateKey) {
	t.Helper()
	message, err := grantBytes(r.Authorization.Grant)
	if err != nil {
		t.Fatal(err)
	}
	r.Authorization.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, message))
}

func TestGrantAuthorization(t *testing.T) {
	r, key, _, now := signedRequest(t)
	if err := verify(r, key, "broker-installation", testBinding(), now); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"installation", "tenant", "host", "session", "endpoint", "execution", "generation", "attempt", "spec", "operation", "target", "audience", "expiry", "future", "long-window", "signature", "version"} {
		t.Run(field, func(t *testing.T) {
			r, key, private, now := signedRequest(t)
			scope := testBinding()
			g := &r.Authorization.Grant
			switch field {
			case "installation":
				scope.InstallationID = "other"
			case "tenant":
				scope.TenantID = "other"
			case "host":
				scope.HostID = "other"
			case "session":
				scope.SessionEpoch = "4"
			case "endpoint":
				scope.EndpointIdentity = "docker-replaced"
			case "execution":
				g.Binding.ExecutionID = ""
				resign(t, &r, private)
			case "generation":
				g.Binding.Generation = ""
				resign(t, &r, private)
			case "attempt":
				g.Binding.AttemptID = ""
				resign(t, &r, private)
			case "spec":
				g.Binding.SpecHash = "invalid"
				resign(t, &r, private)
			case "operation":
				r.Operation = "StartExecution"
			case "target":
				r.Target = strings.Repeat("c", 64)
			case "audience":
				g.Audience = "other"
				resign(t, &r, private)
			case "expiry":
				now = now.Add(30 * time.Second)
			case "future":
				now = now.Add(-2 * time.Second)
			case "long-window":
				g.ExpiresAt = now.Add(2 * time.Minute).Format(time.RFC3339Nano)
				resign(t, &r, private)
			case "signature":
				r.Authorization.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
			case "version":
				r.Version = "other"
			}
			if verify(r, key, "broker-installation", scope, now) == nil {
				t.Fatal("unauthorized grant accepted")
			}
		})
	}
}

func TestStrictProtocol(t *testing.T) {
	for _, raw := range []string{`{"version":"runnerd-broker-v1","operation":"GetBrokerHealth","operation":"StartExecution"}`, `{"version":"runnerd-broker-v1","operation":"GetBrokerHealth","path":"/etc"}`, `{} {}`, `null`, strings.Repeat(" ", MaxMessage+1)} {
		var request Request
		err := decode([]byte(raw), &request)
		// null has no valid protocol version and is refused by the handler.
		if err == nil && request.Version == Version {
			t.Fatalf("accepted ambiguous/unknown input: %s", raw)
		}
	}
}

func TestLedgerOriginalIntentSurvivesRestart(t *testing.T) {
	l, path := testLedger(t)
	id := strings.Repeat("b", 64)
	want, duplicate, err := l.Begin(id, "CreateExecution", testBinding(), []byte("original immutable plan"))
	if err != nil || duplicate || want.State != "RECOVERY_REQUIRED" {
		t.Fatalf("intent: %+v %v %v", want, duplicate, err)
	}
	if _, err := OpenLedger(path); err == nil {
		t.Fatal("second physical owner accepted")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got, duplicate, err := l.Begin(id, "CreateExecution", testBinding(), []byte("original immutable plan"))
	if err != nil || !duplicate || got != want {
		t.Fatalf("lost-reply reconciliation changed original: %+v %v %v", got, duplicate, err)
	}
	if _, _, err := l.Begin(id, "CreateExecution", testBinding(), []byte("replacement plan")); err != ErrConflict {
		t.Fatalf("conflicting retry: %v", err)
	}
	other := testBinding()
	other.Generation = "3"
	if _, _, err := l.Begin(id, "CreateExecution", other, []byte("original immutable plan")); err != ErrConflict {
		t.Fatalf("generation substitution: %v", err)
	}
	if _, _, err := l.Begin("../../etc/passwd", "CreateExecution", other, nil); err == nil {
		t.Fatal("arbitrary path accepted")
	}
}

func TestLedgerCorruptionCannotAuthorizeRetry(t *testing.T) {
	l, path := testLedger(t)
	id := strings.Repeat("b", 64)
	// Model power loss during intent write: file exists but does not establish a
	// valid durable intent. No replacement or successful completion is inferred.
	if err := os.WriteFile(filepath.Join(path, id+".json"), []byte(`{"version":`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.Begin(id, "CreateExecution", testBinding(), nil); err == nil {
		t.Fatal("partial intent permitted replacement")
	}
	raw, _ := os.ReadFile(filepath.Join(path, id+".json"))
	if string(raw) != `{"version":` {
		t.Fatal("partial evidence overwritten")
	}
}

func TestConcurrentDuplicateIntent(t *testing.T) {
	l, _ := testLedger(t)
	var wg sync.WaitGroup
	created := make(chan bool, 16)
	for range 16 {
		wg.Go(func() {
			_, duplicate, err := l.Begin(strings.Repeat("b", 64), "StartExecution", testBinding(), []byte("same"))
			if err != nil {
				t.Error(err)
			}
			created <- !duplicate
		})
	}
	wg.Wait()
	close(created)
	n := 0
	for first := range created {
		if first {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d original intents", n)
	}
}

func TestHandlerAuthorityAndNoMutationSurface(t *testing.T) {
	l, _ := testLedger(t)
	r, public, _, _ := signedRequest(t)
	if _, _, err := l.Begin(r.Target, "CreateExecution", testBinding(), []byte("original")); err != nil {
		t.Fatal(err)
	}
	h := handler{config: Config{ControllerUID: 1234, Audience: "broker-installation", Scope: testBinding()}, key: public, ledger: l}
	for _, tc := range []struct {
		name    string
		uid     uint32
		request Request
		status  int
	}{
		{"health", 1234, Request{Version: Version, Operation: "GetBrokerHealth"}, 200},
		{"wrong-peer", 1235, Request{Version: Version, Operation: "GetBrokerHealth"}, 403},
		{"wrong-version", 1234, Request{Version: "v99", Operation: "GetBrokerHealth"}, 409},
		{"unsigned", 1234, Request{Version: Version, Operation: "GetOperationStatus", Target: r.Target}, 403},
		{"signed-status", 1234, r, 200},
		{"shell", 1234, Request{Version: Version, Operation: "ExecuteShellCommand"}, 400},
		{"create-not-yet-supported", 1234, Request{Version: Version, Operation: "CreateExecution"}, 400},
		{"start-not-enabled", 1234, Request{Version: Version, Operation: "StartExecution"}, 400},
		{"remove-not-enabled", 1234, Request{Version: Version, Operation: "RemoveExecution"}, 400},
		{"executor-not-exposed", 1234, Request{Version: Version, Operation: "ExecutePhysicalOperation"}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.request)
			req := httptest.NewRequest(http.MethodPost, "/v1/request", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(context.WithValue(req.Context(), caller{}, tc.uid))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var response Response
			if json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Ready {
				t.Fatal("foundation advertised readiness")
			}
		})
	}
	// Independently valid grant for another generation cannot inspect old receipt.
	r, public, private, _ := signedRequest(t)
	r.Authorization.Grant.Binding.Generation = "3"
	resign(t, &r, private)
	h.key = public
	body, _ := json.Marshal(r)
	req := httptest.NewRequest(http.MethodPost, "/v1/request", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), caller{}, uint32(1234)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("wrong original generation accepted")
	}
}

func TestActualUnixPeerCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		uid, err := peerUID(conn)
		if err == nil && uid != uint32(os.Geteuid()) {
			err = ErrRejected
		}
		result <- err
	}()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestUnsafeLedgerDirectoryRejected(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	if l, err := OpenLedger(path); err == nil {
		l.Close()
		t.Fatal("unprotected ledger accepted")
	}
}

func TestLedgerRejectsUnknownFormatAndSymlink(t *testing.T) {
	for _, kind := range []string{"symlink", "future-version", "false-cleanup"} {
		t.Run(kind, func(t *testing.T) {
			l, path := testLedger(t)
			id := strings.Repeat("b", 64)
			receipt := Receipt{Version: Version, OperationID: id, Operation: "CreateExecution", Binding: testBinding(), PayloadHash: strings.Repeat("a", 64), State: "RECOVERY_REQUIRED"}
			if kind == "future-version" {
				receipt.Version = "runnerd-broker-v99"
			}
			if kind == "false-cleanup" {
				receipt.State = "CLEANED"
			}
			raw, _ := json.Marshal(receipt)
			file := filepath.Join(path, id+".json")
			if kind == "symlink" {
				target := filepath.Join(path, "original.json")
				if err := os.WriteFile(target, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, file); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := l.Get(id); err == nil {
				t.Fatal("unsafe ledger accepted")
			}
			if _, _, err := l.Begin(id, "CreateExecution", testBinding(), nil); err == nil {
				t.Fatal("unsafe ledger replaced")
			}
		})
	}
}

func TestClientRejectsNonRootSocketPeer(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root impersonation requires non-root test invocation")
	}
	path := filepath.Join(t.TempDir(), "broker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.AcceptUnix()
		if err == nil {
			conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Call(ctx, path, Request{Version: Version, Operation: "GetBrokerHealth"}); err == nil {
		t.Fatal("fake non-root broker accepted")
	}
	<-done
}

func TestBrokerIntentCrashHelper(t *testing.T) {
	path := os.Getenv("NETICORA_BROKER_TEST_CRASH_PATH")
	if path == "" {
		return
	}
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	marker := "intent-durable\n"
	if os.Getenv("NETICORA_BROKER_TEST_CONSUME_ONLY") == "1" {
		r, s, key, private, now := executionFixture(t, "PrepareImage")
		commit := freshChallenge(t, l, &r, &s, private, now)
		l.mu.Lock()
		_, err = l.consumeChallenge(s, r, commit, key, now)
		l.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		marker = "challenge-durable\n"
	} else if _, _, err = l.Begin(strings.Repeat("b", 64), "CreateExecution", testBinding(), []byte("original")); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stdout.WriteString(marker); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Hour)
}

func TestIntentSurvivesBrokerSIGKILL(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestBrokerIntentCrashHelper$")
	command.Env = append(os.Environ(), "NETICORA_BROKER_TEST_CRASH_PATH="+path)
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
		ready <- err == nil && line == "intent-durable\n"
	}()
	select {
	case ok := <-ready:
		if !ok {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatal("child did not persist original intent")
		}
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("child intent timed out")
	}
	if err = command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = command.Wait(); err == nil {
		t.Fatal("child did not die")
	}
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	r, duplicate, err := l.Begin(strings.Repeat("b", 64), "CreateExecution", testBinding(), []byte("original"))
	if err != nil || !duplicate || r.State != "RECOVERY_REQUIRED" {
		t.Fatalf("crash lost obligation: %+v %v %v", r, duplicate, err)
	}
	if _, _, err = l.Begin(strings.Repeat("b", 64), "CreateExecution", testBinding(), []byte("replacement")); err != ErrConflict {
		t.Fatal("crash allowed replacement")
	}
}
