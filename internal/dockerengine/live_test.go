//go:build linux && runnerd_docker

package dockerengine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
)

// Explicit disposable-lab only. These tests qualify engine mechanics, not the
// GitHub template, provider outcome, image-signing authority or a production host.
func TestRealDockerResourceEnforcementAndOwnedCleanup(t *testing.T) {
	endpoint, image, network := os.Getenv("RUNNERD07_DOCKER_ENDPOINT"), os.Getenv("RUNNERD07_DOCKER_IMAGE"), os.Getenv("RUNNERD07_DOCKER_NETWORK")
	cli := os.Getenv("RUNNERD07_DOCKER_CLI")
	if endpoint == "" || !strings.Contains(image, "@sha256:") || len(network) != 64 || cli == "" {
		t.Fatal("explicit lab endpoint, pinned image, network ID and Docker CLI required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal("disposable Runnerd VM required")
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	installation := "qualification-" + hex.EncodeToString(nonce)
	e, err := Open(endpoint, installation, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binding, err := e.Probe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("endpoint binding", binding)
	img, err := e.api.ImageInspect(ctx, image)
	if err != nil || img.Config == nil {
		t.Fatal("stage the pinned lab image before testing", err)
	}
	for _, scenario := range []string{"cpu", "pids", "oom"} {
		t.Run(scenario, func(t *testing.T) {
			labels := map[string]string{}
			for k, v := range img.Config.Labels {
				labels[k] = v
			}
			labels[LabelPrefix+"installation"] = installation
			pids := int64(32)
			program := "import time; time.sleep(90)"
			if scenario == "cpu" {
				program = "import os\nfor _ in range(2):\n if os.fork()==0: break\nx=0\nwhile True: x=(x+1)%10000"
			}
			if scenario == "oom" {
				program = "import time; time.sleep(1); x=bytearray(512*1024*1024); time.sleep(60)"
			}
			p := Plan{Name: "nrd-" + installation + "-" + scenario, Config: &container.Config{Image: image, User: "10001:10001", WorkingDir: "/", Entrypoint: []string{"/usr/bin/python3"}, Cmd: []string{"-c", program}, Labels: labels}, HostConfig: &container.HostConfig{RestartPolicy: container.RestartPolicy{Name: "no"}, IpcMode: "private", NetworkMode: container.NetworkMode(network), CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges=true"}, Resources: container.Resources{NanoCPUs: 1_000_000_000, Memory: 128 * 1024 * 1024, MemorySwap: 128 * 1024 * 1024, PidsLimit: &pids}, LogConfig: container.LogConfig{Type: "local", Config: map[string]string{"max-size": "1m", "max-file": "2", "mode": "non-blocking", "max-buffer-size": "1m"}}}}
			claims := 0
			o, err := e.Ensure(ctx, p, func() error { claims++; return nil })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
				defer stop()
				if err := e.Stop(cleanup, o.ID, p); err != nil {
					t.Error(err)
				}
				if err := e.Remove(cleanup, o.ID, p); err != nil {
					t.Error(err)
				}
			})
			o, err = e.Start(ctx, o.ID, p, func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			adopted, err := e.Ensure(ctx, p, func() error { claims++; return nil })
			if err != nil || adopted.ID != o.ID || claims != 1 {
				t.Fatal("duplicate creation/adoption", err)
			}
			run := func(args ...string) ([]byte, error) {
				return exec.CommandContext(ctx, cli, append([]string{"-H", endpoint, "exec", o.ID}, args...)...).CombinedOutput()
			}
			switch scenario {
			case "cpu":
				quota, err := run("cat", "/sys/fs/cgroup/cpu.max")
				if err != nil {
					t.Fatal(err)
				}
				parts := strings.Fields(string(quota))
				if len(parts) != 2 {
					t.Fatal("CPU quota missing")
				}
				q, _ := strconv.Atoi(parts[0])
				period, _ := strconv.Atoi(parts[1])
				if q <= 0 || q != period {
					t.Fatal("CPU ceiling not enforced")
				}
				time.Sleep(2 * time.Second)
				stats, err := run("cat", "/sys/fs/cgroup/cpu.stat")
				if err != nil {
					t.Fatal(err)
				}
				throttled := false
				for _, line := range strings.Split(string(stats), "\n") {
					fields := strings.Fields(line)
					if len(fields) == 2 && fields[0] == "nr_throttled" {
						n, _ := strconv.Atoi(fields[1])
						throttled = n > 0
					}
				}
				if !throttled {
					t.Fatal("CPU workload did not demonstrate throttling")
				}
				t.Log("CPU quota and cgroup throttling verified")
			case "pids":
				script := "import os,time,signal\nchildren=[]\ntry:\n for _ in range(64):\n  pid=os.fork()\n  if pid==0: time.sleep(2); os._exit(0)\n  children.append(pid)\nexcept OSError as e:\n if e.errno==11: print('PID_LIMIT_HIT')\nfinally:\n for p in children:\n  os.waitpid(p,0)"
				out, err := run("python3", "-c", script)
				if err != nil || !strings.Contains(string(out), "PID_LIMIT_HIT") {
					t.Fatalf("PID ceiling not demonstrated: %v; synthetic probe: %.1024s", err, out)
				}
				t.Log("PID exhaustion contained by execution cgroup")
			case "oom":
				deadline := time.Now().Add(20 * time.Second)
				for time.Now().Before(deadline) {
					o, err = e.Inspect(ctx, o.ID, p)
					if err != nil {
						t.Fatal(err)
					}
					if o.State == "exited" {
						break
					}
					time.Sleep(200 * time.Millisecond)
				}
				if o.State != "exited" || !o.OOMKilled || o.ExitCode != 137 {
					t.Fatalf("OOM evidence missing: %+v", o)
				}
				t.Log("memory ceiling and independent runtime OOM observation verified")
			}
			if err = e.Stop(ctx, o.ID, p); err != nil {
				t.Fatal(err)
			}
			if err = e.Remove(ctx, o.ID, p); err != nil {
				t.Fatal(err)
			}
			if _, err = e.Inspect(ctx, o.ID, p); err != ErrAbsent {
				t.Fatal("absence not established", err)
			}
			ids, err := e.Inventory(ctx)
			if err != nil || len(ids) != 0 {
				t.Fatal("owned cleanup incomplete", err)
			}
		})
	}
}
