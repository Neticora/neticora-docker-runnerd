//go:build linux && runnerd_docker

package dockerengine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/journal"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func socketLab(t *testing.T) {
	t.Helper()
	if os.Getenv("RUNNERD_SOCKET_ACTIVATION_TEST") != "1" {
		t.Skip("explicit disposable socket activation qualification required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal("disposable Runnerd VM required")
	}
}

func TestStandardSocketActivationReadOnly(t *testing.T) {
	socketLab(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	e, err := OpenReadOnly("unix:///run/docker.sock", "socket-activation-observation", func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	peer, err := e.Probe(ctx)
	if os.Getenv("RUNNERD_SOCKET_EXPECT_DENIED") == "1" {
		if !errors.Is(err, ErrPermission) {
			t.Fatal("missing effective account permission diagnosis", err)
		}
		t.Log("specific permission failure; no Docker mutation or enrollment request")
		return
	}
	if err != nil || !strings.HasPrefix(peer, "docker-") {
		t.Fatal("standard socket activation unavailable", err)
	}
	t.Log("actual dockerd binding", peer)
	for _, mutation := range []func() error{
		func() error { _, err := e.Ensure(ctx, Plan{}, func() error { return nil }); return err },
		func() error { _, err := e.Start(ctx, "not-owned", Plan{}, func() error { return nil }); return err },
		func() error { return e.Stop(ctx, "not-owned", Plan{}) },
		func() error { return e.Remove(ctx, "not-owned", Plan{}) },
	} {
		if err := mutation(); !errors.Is(err, ErrRecoveryApprovalRequired) {
			t.Fatal("observation granted mutation authority", err)
		}
	}
}

func socketStart(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(os.Getenv("RUNNERD_ACTIVATION_START_FIXTURE"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Schema string
		Value  json.RawMessage
		Valid  bool
	}
	if json.Unmarshal(raw, &fixtures) != nil {
		t.Fatal("invalid corpus")
	}
	var start map[string]any
	for _, f := range fixtures {
		if f.Schema == "HostCommand" && f.Valid {
			var m map[string]any
			if json.Unmarshal(f.Value, &m) == nil && m["kind"] == "start" {
				start = m
				break
			}
		}
	}
	if start == nil {
		t.Fatal("missing start fixture")
	}
	digest := func(v any) string {
		raw, _ := json.Marshal(v)
		canonical, err := protocol.CanonicalizeJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(canonical)
		return hex.EncodeToString(sum[:])
	}
	spec := start["spec"].(map[string]any)
	spec["authorizationExpiresAt"] = time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
	delete(spec, "specHash")
	spec["specHash"] = digest(spec)
	delete(start, "payloadHash")
	start["payloadHash"] = digest(start)
	raw, _ = json.Marshal(start)
	return raw
}

func TestStandardSocketActivationRestartFencing(t *testing.T) {
	socketLab(t)
	if os.Geteuid() != 0 {
		t.Fatal("root disposable restart coordinator required")
	}
	control := os.Getenv("RUNNERD_ACTIVATION_CONTROL")
	image := os.Getenv("RUNNERD_ACTIVATION_IMAGE")
	if !strings.HasPrefix(control, "/var/tmp/runnerd-socket-") || filepath.Clean(control) != control || !strings.Contains(image, "@sha256:") {
		t.Fatal("bounded private control and pinned lab image required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	installation := fmt.Sprintf("socket-qualification-%d", os.Getpid())
	current, err := Open("unix:///run/docker.sock", installation, func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	peer, err := current.Probe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	img, err := current.api.ImageInspect(ctx, image)
	if err != nil || img.Config == nil {
		t.Fatal("pinned minimal fixture missing", err)
	}
	labels := map[string]string{}
	for k, v := range img.Config.Labels {
		labels[k] = v
	}
	labels[LabelPrefix+"installation"] = installation
	labels[LabelPrefix+"endpoint"] = peer
	pids := int64(16)
	plan := Plan{Name: "nrd-" + installation, Config: &container.Config{Image: image, User: "65534:65534", WorkingDir: "/", Entrypoint: []string{"/bin/sh"}, Cmd: []string{"-c", "sleep 300"}, Labels: labels}, HostConfig: &container.HostConfig{NetworkMode: "none", IpcMode: "private", RestartPolicy: container.RestartPolicy{Name: "no"}, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges=true"}, Resources: container.Resources{Memory: 32 << 20, MemorySwap: 32 << 20, PidsLimit: &pids}, LogConfig: container.LogConfig{Type: "local", Config: map[string]string{"max-size": "1m", "max-file": "2"}}}}
	dir := filepath.Join(control, "creation-journal")
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	fence, err := journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fence.Close() })
	start := socketStart(t)
	authority := journal.Authority{TenantID: "tenant-a", HostID: "host-a", SessionEpoch: "1", EndpointIdentity: peer, KeyID: "key-a"}
	claims := 0
	object, err := current.Ensure(ctx, plan, func() error { claims++; return fence.ClaimCreation(start, authority) })
	if err != nil {
		inspected, inspectErr := current.api.ContainerInspect(ctx, plan.Name, client.ContainerInspectOptions{})
		if inspectErr == nil {
			data, _ := json.Marshal(map[string]any{"ownedFixture": inspected.Container, "expectedHostConfig": plan.HostConfig})
			_ = os.WriteFile(filepath.Join(control, "fixture-create-failure.json"), data, 0600)
		}
		t.Fatal(err)
	}
	// Cleanup is explicit lab authority over this inspected ID only, not a grant
	// to the recovered read-only execution adapter or a platform disposal claim.
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		cli, err := client.New(client.WithHost("unix:///run/docker.sock"), client.WithAPIVersionNegotiation())
		if err != nil {
			t.Error(err)
			return
		}
		defer cli.Close()
		ins, err := cli.ContainerInspect(cleanup, object.ID, client.ContainerInspectOptions{})
		if err != nil {
			t.Error(err)
			return
		}
		if ins.Container.Config.Labels[LabelPrefix+"installation"] != installation {
			t.Error("cleanup owner mismatch")
			return
		}
		_, err = cli.ContainerRemove(cleanup, object.ID, client.ContainerRemoveOptions{Force: true})
		if err != nil {
			t.Error(err)
		}
	})
	if _, err = current.Start(ctx, object.ID, plan, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	markers, err := filepath.Glob(filepath.Join(dir, "*.creation.json"))
	if err != nil || len(markers) != 1 {
		t.Fatal("missing native durable creation marker")
	}
	markerBefore, err := os.ReadFile(markers[0])
	if err != nil {
		t.Fatal(err)
	}
	markerHash := sha256.Sum256(markerBefore)
	for _, phase := range []string{"daemon-restart", "socket-recreation"} {
		meta := map[string]any{"phase": phase, "containerId": object.ID, "endpointBefore": peer, "journalSha256": hex.EncodeToString(markerHash[:]), "claims": claims}
		data, _ := json.Marshal(meta)
		if err = os.WriteFile(filepath.Join(control, phase+".ready.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		for {
			if _, err = os.Stat(filepath.Join(control, phase+".done")); err == nil {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("restart coordinator timeout")
			case <-time.After(100 * time.Millisecond):
			}
		}
		if _, err = current.Inspect(ctx, object.ID, plan); !errors.Is(err, ErrUnavailable) {
			t.Fatal("old engine accepted restarted peer", err)
		}
		if _, err = current.Inventory(ctx); !errors.Is(err, ErrUnavailable) {
			t.Fatal("old engine trusted restarted inventory", err)
		}
		fresh, err := OpenReadOnly("unix:///run/docker.sock", installation, func() {})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = fresh.Close() })
		after, err := fresh.Probe(ctx)
		if err != nil || after == peer {
			t.Fatal("restart did not fence daemon identity", err)
		}
		inspected, err := fresh.Inspect(ctx, object.ID, plan)
		if err != nil || inspected.ID != object.ID || inspected.State == "running" {
			t.Fatal("original owned resource lost or automatically restarted", err)
		}
		if _, err = fresh.Ensure(ctx, plan, func() error { claims++; return nil }); !errors.Is(err, ErrRecoveryApprovalRequired) {
			t.Fatal("recovery admitted a replacement create", err)
		}
		if _, err = fresh.Start(ctx, object.ID, plan, func() error { return nil }); !errors.Is(err, ErrRecoveryApprovalRequired) {
			t.Fatal("recovery admitted start", err)
		}
		if err = fresh.Remove(ctx, object.ID, plan); !errors.Is(err, ErrRecoveryApprovalRequired) {
			t.Fatal("recovery admitted disposal", err)
		}
		if err = fence.Close(); err != nil {
			t.Fatal(err)
		}
		fence, err = journal.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		renewed := authority
		renewed.EndpointIdentity = after
		if err = fence.ClaimCreation(start, renewed); !errors.Is(err, journal.ErrFenced) {
			t.Fatal("journal reuse permitted after restart", err)
		}
		markerAfter, err := os.ReadFile(markers[0])
		if err != nil || sha256.Sum256(markerAfter) != markerHash || claims != 1 {
			t.Fatal("original journal or creation fence changed")
		}
		meta["endpointAfter"] = after
		meta["readOnlyRecovery"] = true
		meta["journalUnchanged"] = true
		data, _ = json.Marshal(meta)
		if err = os.WriteFile(filepath.Join(control, phase+".verified.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		_ = current.Close()
		current = fresh
		peer = after
		t.Log(phase, "retained original object and journal; duplicate create/start/disposal fenced")
	}
}
