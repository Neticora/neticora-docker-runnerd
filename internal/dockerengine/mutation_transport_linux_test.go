//go:build linux

package dockerengine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// This root-only case exercises the production SO_PEERCRED reader against two
// real processes and an actual Unix socket-path replacement. It needs no Docker,
// daemon restart, network rule or signing authority. Ordinary non-root CI still
// exercises the deterministic four-mutation transport regression.
func TestMutationTransportRealSocketReplacement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned subprocess peers required; run on the disposable lab VM")
	}
	for _, operation := range []string{"create", "start", "stop", "remove"} {
		t.Run(operation, func(t *testing.T) {
			directory, err := os.MkdirTemp("", "nrd-peer-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(directory) })
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			// The kernel comm name is dockerd; identity checks otherwise use the
			// real UID/PID/process-start/boot ID with no injected peer observer.
			helper := filepath.Join(directory, "dockerd")
			if err = os.Symlink(binary, helper); err != nil {
				t.Fatal(err)
			}
			p := Plan{Name: "owned", Config: &container.Config{Image: "example/runner@sha256:" + strings.Repeat("a", 64), User: "10001:10001", WorkingDir: "/runner", Entrypoint: []string{"/usr/local/bin/runnerd-github"}, Labels: map[string]string{LabelPrefix + "installation": "install-a"}}, HostConfig: &container.HostConfig{RestartPolicy: container.RestartPolicy{Name: "no"}, IpcMode: "private", CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges=true"}}}
			raw, _ := json.Marshal(p)
			planFile := filepath.Join(directory, "plan.json")
			if err = os.WriteFile(planFile, raw, 0600); err != nil {
				t.Fatal(err)
			}
			start := func(socket, role string) {
				cmd := exec.Command(helper, "-test.run=^TestDockerMutationPeerHelper$")
				cmd.Env = append(os.Environ(), "NRD_MUTATION_HELPER=1", "NRD_MUTATION_SOCKET="+socket, "NRD_MUTATION_ROLE="+role, "NRD_MUTATION_OPERATION="+operation, "NRD_MUTATION_PLAN="+planFile)
				cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
				deadline := time.Now().Add(10 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := os.Stat(socket + ".ready"); err == nil {
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
				t.Fatal("socket helper readiness deadline")
			}
			socket, replacement := filepath.Join(directory, "original.sock"), filepath.Join(directory, "replacement.sock")
			start(socket, "original")
			start(replacement, "replacement")
			e, err := Open("unix://"+socket, "install-a", nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = e.Close() })
			injected := false
			api, err := client.New(client.WithHost("unix://"+socket), client.WithDialContext(e.dialContext), client.WithAPIVersion("1.52"), client.WithHTTPRequestHook(func(request *http.Request) error {
				if request.Method == http.MethodPost || request.Method == http.MethodDelete {
					injected = true
					if err := os.Rename(replacement, socket); err != nil {
						return err
					}
					_ = e.api.Close()
				}
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			_ = e.api.Close()
			e.api = api
			switch operation {
			case "create":
				_, err = e.Ensure(context.Background(), p, func() error { return nil })
			case "start":
				_, err = e.Start(context.Background(), "owned", p, func() error { return nil })
			case "stop":
				err = e.Stop(context.Background(), "owned", p)
			case "remove":
				err = e.Remove(context.Background(), "owned", p)
			}
			if !injected || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("mutation not fenced: injected=%v err=%v", injected, err)
			}
			for _, path := range []string{socket + ".mutations", replacement + ".mutations"} {
				requests, err := os.ReadFile(path)
				if err != nil || len(requests) != 0 {
					t.Fatalf("peer received mutation bytes: %q %v", requests, err)
				}
			}
		})
	}
}

func TestDockerMutationPeerHelper(t *testing.T) {
	if os.Getenv("NRD_MUTATION_HELPER") != "1" {
		t.Skip("subprocess helper only")
	}
	socket, role, operation := os.Getenv("NRD_MUTATION_SOCKET"), os.Getenv("NRD_MUTATION_ROLE"), os.Getenv("NRD_MUTATION_OPERATION")
	var p Plan
	raw, err := os.ReadFile(os.Getenv("NRD_MUTATION_PLAN"))
	if err != nil || json.Unmarshal(raw, &p) != nil {
		t.Fatal("invalid synthetic plan")
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = os.WriteFile(socket+".mutations", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(socket+".ready", []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Api-Version", "1.52")
		path := strings.TrimPrefix(r.URL.Path, "/v1.52")
		if r.Method == http.MethodPost || r.Method == http.MethodDelete {
			file, err := os.OpenFile(socket+".mutations", os.O_WRONLY|os.O_APPEND, 0600)
			if err == nil {
				_, _ = file.WriteString(r.Method + "\n")
				_ = file.Close()
			}
			http.Error(w, `{"message":"unexpected mutation"}`, 500)
			return
		}
		if path == "/info" {
			_ = json.NewEncoder(w).Encode(map[string]any{"ID": role, "OSType": "linux"})
			return
		}
		if path == "/_ping" {
			w.WriteHeader(200)
			return
		}
		if strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json") {
			if operation == "create" {
				http.Error(w, `{"message":"absent"}`, 404)
				return
			}
			cfg := *p.Config
			cfg.Env = []string{"HOME=/runner"}
			state := "created"
			if operation == "stop" {
				state = "running"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": "owned", "Image": "sha256:" + strings.Repeat("b", 64), "Config": cfg, "HostConfig": p.HostConfig, "State": map[string]any{"Status": state, "Running": state == "running"}})
			return
		}
		if strings.HasPrefix(path, "/images/") {
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": "sha256:" + strings.Repeat("b", 64), "Config": map[string]any{"Env": []string{"HOME=/runner"}}})
			return
		}
		http.NotFound(w, r)
	})}
	if err = server.Serve(listener); err != nil {
		t.Fatal(err)
	}
}
