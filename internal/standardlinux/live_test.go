//go:build linux && runnerd_docker

package standardlinux

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

// This checks the actual process-only plan against Docker's normalized inspect
// response. No provider credentials or production admission authority is used.
func TestRealStandardTemplateRejectsMissingBootstrapAndCleansOwnedObject(t *testing.T) {
	endpoint, image, network := os.Getenv("RUNNERD07_DOCKER_ENDPOINT"), os.Getenv("RUNNERD07_DOCKER_IMAGE"), os.Getenv("RUNNERD07_DOCKER_NETWORK")
	parts := strings.Split(image, "@")
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil || os.Geteuid() == 0 || endpoint == "" || len(parts) != 2 || !strings.HasPrefix(parts[1], "sha256:") || len(network) != 64 {
		t.Fatal("disposable non-root VM and explicit pinned runtime inputs required")
	}
	root, err := os.MkdirTemp("/dev/shm", "runnerd07-template-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(root)
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	installation := "qualification-" + hex.EncodeToString(nonce)
	runtime, err := dockerengine.Open(endpoint, installation, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	binding, err := runtime.Probe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scope := agent.StoreScope{InstallationID: installation, TenantID: "qualification", HostID: "qualification", SessionEpoch: "1", EndpointIdentity: binding}
	spec := protocol.ExecutionSpec{ExecutionId: installation, Generation: "1", AttemptId: installation, SpecHash: strings.Repeat("a", 64), ImageDigest: parts[1], Resources: protocol.ResourceBudget{CpuMillis: "1000", MemoryBytes: "536870912", StorageBytes: "67108864", Slots: "1"}}
	settings := Settings{ImageRepository: parts[0], NetworkID: network, BootstrapRoot: root, RunnerUID: os.Geteuid(), PidsLimit: 128}
	plan, err := settings.Plan(scope, spec)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, plan.Name)
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(dir)
	if err = runtime.PrepareImage(ctx, plan); err != nil {
		t.Fatal("template/image contract rejected", err)
	}
	claims := 0
	object, err := runtime.Ensure(ctx, plan, func() error { claims++; return nil })
	if err != nil {
		t.Fatal("actual Standard inspect configuration rejected", err)
	}
	resourceID := object.ID
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := runtime.Stop(cleanup, resourceID, plan); err != nil {
			t.Error(err)
		}
		if err := runtime.Remove(cleanup, resourceID, plan); err != nil {
			t.Error(err)
		}
	})
	object, err = runtime.Start(ctx, object.ID, plan, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for object.State != "exited" && ctx.Err() == nil {
		time.Sleep(100 * time.Millisecond)
		object, err = runtime.Inspect(ctx, object.ID, plan)
		if err != nil {
			t.Fatal(err)
		}
	}
	if object.State != "exited" || object.ExitCode != 1 || claims != 1 {
		t.Fatalf("missing handoff not rejected: %+v", object)
	}
	if _, err = runtime.Start(ctx, object.ID, plan, func() error { return nil }); !errors.Is(err, dockerengine.ErrConflict) {
		t.Fatal("exited listener restarted", err)
	}
	if err = runtime.Remove(ctx, object.ID, plan); err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.Inspect(ctx, object.ID, plan); !errors.Is(err, dockerengine.ErrAbsent) {
		t.Fatal("owned template absence unproven", err)
	}
	t.Log("actual Standard plan accepted; non-root wrapper rejected missing handoff; no restart; owned cleanup verified")
}
