package dockerengine

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
)

func fakeEngine(t *testing.T) (*Engine, Plan, *bool, *bool, *int, *string) {
	return fakeEngineWithHook(t, nil)
}

func fakeEngineWithHook(t *testing.T, hook func(string)) (*Engine, Plan, *bool, *bool, *int, *string) {
	t.Helper()
	exists, running := false, false
	creates := 0
	daemon := "engine-a"
	root := t.TempDir()
	p := Plan{Name: "owned", Config: &container.Config{Image: "example/runner@sha256:" + strings.Repeat("a", 64), User: "10001:10001", WorkingDir: "/runner", Entrypoint: []string{"/usr/local/bin/runnerd-github"}, Labels: map[string]string{LabelPrefix + "installation": "install-a"}}, HostConfig: &container.HostConfig{RestartPolicy: container.RestartPolicy{Name: "no"}, IpcMode: "private", CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges=true"}}}
	socket := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Api-Version", "1.52")
		path := strings.TrimPrefix(r.URL.Path, "/v1.52")
		if hook != nil {
			hook(path)
		}
		switch {
		case path == "/_ping":
			w.WriteHeader(200)
		case path == "/info":
			_ = json.NewEncoder(w).Encode(map[string]any{"ID": daemon, "OSType": "linux", "DockerRootDir": root})
		case path == "/containers/json":
			_ = json.NewEncoder(w).Encode([]any{})
		case strings.HasPrefix(path, "/images/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": "sha256:" + strings.Repeat("b", 64), "Config": map[string]any{"Env": []string{"HOME=/runner"}}})
		case path == "/containers/create":
			exists = true
			creates++
			http.Error(w, `{"message":"create reply lost"}`, 500)
		case strings.HasSuffix(path, "/start"):
			running = true
			w.WriteHeader(204)
		case strings.HasSuffix(path, "/json"):
			if !exists {
				http.Error(w, `{"message":"absent"}`, 404)
				return
			}
			cfg := *p.Config
			cfg.Env = []string{"HOME=/runner"}
			state := "created"
			if running {
				state = "running"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": strings.Repeat("c", 64), "Image": "sha256:" + strings.Repeat("b", 64), "Config": cfg, "HostConfig": p.HostConfig, "State": map[string]any{"Status": state, "Running": running}})
		default:
			http.Error(w, `{"message":"unexpected mutation"}`, 400)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	e, err := Open("unix://"+socket, "install-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	e.observePeer = func(context.Context, string) (string, error) { return "qualified-direct-dockerd-peer", nil }
	e.connectionPeer = func(net.Conn) (string, error) { return "qualified-direct-dockerd-peer", nil }
	return e, p, &exists, &running, &creates, &daemon
}

func TestLostCreateReplyAdoptsWithoutCreatingOrStartingAgain(t *testing.T) {
	e, p, _, running, creates, _ := fakeEngine(t)
	claims := 0
	claim := func() error { claims++; return nil }
	if _, err := e.Ensure(context.Background(), p, claim); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	o, err := e.Ensure(context.Background(), p, claim)
	if err != nil || o.State != "prepared" || *creates != 1 || claims != 1 || *running {
		t.Fatalf("unsafe adoption: %+v %v", o, err)
	}
	if _, err = e.Start(context.Background(), o.ID, p, func() error { return errors.New("expired authority") }); err == nil || *running {
		t.Fatal("expired created container started")
	}
	if _, err = e.Start(context.Background(), o.ID, p, func() error { return nil }); err != nil || !*running {
		t.Fatal(err)
	}
}

func TestHistoricalPlanCanInspectButCannotPrepareCreateOrStart(t *testing.T) {
	requests := 0
	e, p, exists, running, creates, _ := fakeEngineWithHook(t, func(string) { requests++ })
	p.RecoveryOnly = true
	*exists = true
	called := false
	authorize := func() error { called = true; return nil }
	if err := e.PrepareImage(t.Context(), p); !errors.Is(err, ErrRecoveryPlan) {
		t.Fatal("historical image preparation accepted", err)
	}
	if _, err := e.Ensure(t.Context(), p, authorize); !errors.Is(err, ErrRecoveryPlan) {
		t.Fatal("historical create accepted", err)
	}
	if _, err := e.Start(t.Context(), p.Name, p, authorize); !errors.Is(err, ErrRecoveryPlan) {
		t.Fatal("historical start accepted", err)
	}
	if requests != 0 || called || *running || *creates != 0 {
		t.Fatal("historical launch touched the runtime or creation authority")
	}
	if object, err := e.Inspect(t.Context(), p.Name, p); err != nil || object.State != "prepared" {
		t.Fatal("historical inspection blocked", object, err)
	}
}

func TestOwnershipAndRestartDriftPreventMutation(t *testing.T) {
	e, p, exists, _, _, _ := fakeEngine(t)
	*exists = true
	// The server retains the original desired HostConfig pointer. The candidate
	// expects restart=no while the actual inspect reports a changed policy.
	actual := p.HostConfig
	expected := *actual
	p.HostConfig = &expected
	actual.RestartPolicy.Name = "always"
	if _, err := e.Inspect(context.Background(), p.Name, p); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := e.Remove(context.Background(), p.Name, p); !errors.Is(err, ErrConflict) {
		t.Fatal("drift permitted destructive mutation", err)
	}
}

func TestEndpointChangeInvalidatesContinuity(t *testing.T) {
	e, _, _, _, _, daemon := fakeEngine(t)
	lost := 0
	e.invalidated = func() { lost++ }
	first, err := e.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	*daemon = "replacement-engine"
	if _, err = e.Probe(context.Background()); !errors.Is(err, ErrUnavailable) || lost == 0 {
		t.Fatal("continuity change accepted", err)
	}
	second, err := e.Probe(context.Background())
	if err != nil || first == second {
		t.Fatal("replacement retained old binding", err)
	}
}
