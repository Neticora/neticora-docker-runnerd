//go:build linux && runnerd_docker

package dockerengine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func TestRunnerd08DockerDaemonContinuity(t *testing.T) {
	control := os.Getenv("RUNNERD08_CONTROL")
	if control == "" {
		t.Skip("external disposable daemon restart coordinator required")
	}
	if !strings.HasPrefix(control, "/var/tmp/runnerd08-") || filepath.Clean(control) != control {
		t.Fatal("private control path required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal("disposable lab required")
	}
	image, network, endpoint := os.Getenv("RUNNERD07_DOCKER_IMAGE"), os.Getenv("RUNNERD07_DOCKER_NETWORK"), os.Getenv("RUNNERD07_DOCKER_ENDPOINT")
	if !strings.Contains(image, "@sha256:") || len(network) != 64 || endpoint != "unix:///run/runnerd07-docker.sock" {
		t.Fatal("explicit lab tuple required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	installation := "qualification-" + filepath.Base(control)
	e, err := Open(endpoint, installation, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	before, err := e.Probe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	info, err := e.api.Info(ctx, client.InfoOptions{})
	if err != nil {
		t.Fatal(err)
	}
	img, err := e.api.ImageInspect(ctx, image)
	if err != nil || img.Config == nil {
		t.Fatal("pinned image unavailable")
	}
	labels := map[string]string{}
	for k, v := range img.Config.Labels {
		labels[k] = v
	}
	labels[LabelPrefix+"installation"] = installation
	pids := int64(32)
	p := Plan{Name: "nrd-" + installation, Config: &container.Config{Image: image, User: "10001:10001", WorkingDir: "/", Entrypoint: []string{"/usr/bin/python3"}, Cmd: []string{"-c", "import time; time.sleep(170)"}, Labels: labels}, HostConfig: &container.HostConfig{RestartPolicy: container.RestartPolicy{Name: "no"}, IpcMode: "private", NetworkMode: container.NetworkMode(network), CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges=true"}, Resources: container.Resources{Memory: 128 << 20, MemorySwap: 128 << 20, PidsLimit: &pids}}}
	p.HostConfig.LogConfig = container.LogConfig{Type: "local", Config: map[string]string{"max-size": "1m", "max-file": "2"}}
	claims := 0
	o, err := e.Ensure(ctx, p, func() error { claims++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		fresh, err := Open(endpoint, installation, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer fresh.Close()
		if err = fresh.Stop(cleanup, o.ID, p); err != nil {
			t.Error(err)
			return
		}
		if err = fresh.Remove(cleanup, o.ID, p); err != nil {
			t.Error(err)
			return
		}
		if _, err = fresh.Inspect(cleanup, o.ID, p); !errors.Is(err, ErrAbsent) {
			t.Error("owned probe retained", err)
		}
	})
	o, err = e.Start(ctx, o.ID, p, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ready, _ := json.Marshal(map[string]any{"containerId": o.ID, "endpointBefore": before, "liveRestore": info.Info.LiveRestoreEnabled})
	if err = os.WriteFile(filepath.Join(control, "ready.json"), ready, 0600); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err = os.Stat(filepath.Join(control, "restarted")); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("external restart deadline")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if _, err = e.Inspect(ctx, o.ID, p); !errors.Is(err, ErrUnavailable) {
		t.Fatal("old binding accepted daemon restart", err)
	}
	if _, err = e.Inventory(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("old binding trusted restarted inventory", err)
	}
	fresh, err := Open(endpoint, installation, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	after, err := fresh.Probe(ctx)
	if err != nil || after == before {
		t.Fatal("daemon restart did not change continuity", err)
	}
	if err = fresh.CheckHeadroom(ctx, ^uint64(0)); !errors.Is(err, ErrStoragePressure) {
		t.Fatal("unavailable Docker storage admitted", err)
	}
	if err = fresh.CheckHeadroom(ctx, 1); err != nil {
		t.Fatal("Docker data-root headroom unavailable", err)
	}
	obj, err := fresh.Inspect(ctx, o.ID, p)
	if err != nil || obj.ID != o.ID {
		t.Fatal("owned object identity lost", err)
	}
	inspected, err := fresh.api.ContainerInspect(ctx, o.ID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if claims != 1 || inspected.Container.RestartCount != 0 {
		t.Fatal("automatic restart or duplicate creation")
	}
	if info.Info.LiveRestoreEnabled && obj.State != "running" {
		t.Fatal("configured live restore failed")
	}
	if err = fresh.Stop(ctx, o.ID, p); err != nil {
		t.Fatal(err)
	}
	if err = fresh.Remove(ctx, o.ID, p); err != nil {
		t.Fatal(err)
	}
	if _, err = fresh.Inspect(ctx, o.ID, p); !errors.Is(err, ErrAbsent) {
		t.Fatal("cleanup absence unverified", err)
	}
	result, _ := json.Marshal(map[string]any{"result": "pass", "containerId": o.ID, "endpointBefore": before, "endpointAfter": after, "liveRestore": info.Info.LiveRestoreEnabled, "stateAfterRestart": obj.State, "creationClaims": claims, "restartCount": 0, "ownedContainerAbsent": true, "scope": "real Docker mechanics; synthetic owner; no SaaS cleanup authority"})
	if err = os.WriteFile(filepath.Join(control, "result.json"), result, 0600); err != nil {
		t.Fatal(err)
	}
}
