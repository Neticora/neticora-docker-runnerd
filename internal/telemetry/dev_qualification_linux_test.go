//go:build linux && runnerd_telemetry_qualification

package telemetry_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/executionstorage"
	"github.com/Neticora/neticora-docker-runnerd/internal/telemetry"
	"github.com/Neticora/neticora-docker-runnerd/journal"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

// This test never enrolls a host, changes Docker configuration or accesses the
// platform. The coordinator stages one immutable probe image and transient test
// process access; the installed Runnerd service account is not changed.
func TestRunnerd08CustomerTelemetryDev(t *testing.T) {
	if os.Getenv("RUNNERD08_TELEMETRY_DEV") == "" {
		t.Skip("explicit runnerd-dev campaign only")
	}
	host, _ := os.Hostname()
	if host != "neticora-runnerd-dev" || os.Geteuid() != 1000 {
		t.Fatal("runnerd-dev vagrant UID required")
	}
	root := os.Getenv("RUNNERD08_TELEMETRY_DEV")
	if !strings.HasPrefix(root, "/var/tmp/runnerd08-telemetry-") || filepath.Clean(root) != root {
		t.Fatal("private explicit test root required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	mkdir := func(name string) string {
		p := filepath.Join(root, name)
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal("retain original state", err)
		}
		return p
	}
	state, storage := mkdir("journal"), mkdir("executions")
	var image struct{ Reference string }
	raw, err := os.ReadFile(filepath.Join(root, "image.json"))
	if err != nil || json.Unmarshal(raw, &image) != nil || !strings.Contains(image.Reference, "@sha256:") {
		t.Fatal("immutable image", err)
	}
	scope := storetest.Scope
	scope.InstallationID = "telemetry-dev-" + filepath.Base(root)
	engine, err := dockerengine.Open("unix:///run/docker.sock", scope.InstallationID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	scope.EndpointIdentity, err = engine.Probe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := dockerengine.OpenReadOnly("unix:///run/docker.sock", scope.InstallationID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	s, err := journal.OpenRecovery(ctx, state, journal.Options{ReservationLimits: agent.ReservationLimits{CPUMillis: 1000, MemoryBytes: 1 << 30, StorageBytes: 1 << 30, Slots: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	storetest.Reconcile(t, s, scope, "1")
	v := storetest.Object(t, storetest.Start(t, "telemetry"))
	spec := v["spec"].(map[string]any)
	spec["templateVersion"] = "linux-github-disk-v1"
	spec["imageDigest"] = strings.Split(image.Reference, "@")[1]
	spec["resources"] = map[string]any{"cpuMillis": "250", "memoryBytes": "134217728", "storageBytes": "1048576", "slots": "1"}
	start := storetest.Encode(t, "HostCommand", v)
	if _, err = s.AcceptCommand(ctx, scope, start); err != nil {
		t.Fatal(err)
	}
	if err = s.PutStartIntent(ctx, scope, storetest.Intent(t, start)); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Incomplete(ctx, agent.ExecutionCursor{}, 100)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	identity := rows[0].Identity
	manager := executionstorage.Manager{Path: storage, Store: s, Scope: scope}
	r, err := manager.Prepare(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(storage, r.Name)
	st, _ := os.Stat(state)
	ws, _ := os.Stat(storage)
	if st.Sys().(*syscall.Stat_t).Dev != ws.Sys().(*syscall.Stat_t).Dev {
		t.Fatal("test must prove a shared filesystem")
	}
	var fs syscall.Statfs_t
	syscall.Statfs(root, &fs)
	pids := int64(64)
	labels := map[string]string{}
	for k, v := range map[string]string{"installation": scope.InstallationID, "tenant": scope.TenantID, "host": scope.HostID, "execution": identity.ExecutionID, "generation": identity.Generation, "spec": identity.SpecHash, "attempt": identity.AttemptID, "endpoint": scope.EndpointIdentity, "template": "telemetry-fixture"} {
		labels[dockerengine.LabelPrefix+k] = v
	}
	plan := dockerengine.Plan{Name: "nrd-" + strings.TrimPrefix(r.Name, "nrd-"), StorageDirectory: directory, Config: &container.Config{Image: image.Reference, User: "1000:1000", WorkingDir: "/tmp", Entrypoint: []string{"/bin/sh"}, Cmd: []string{"-c", "dd if=/dev/zero of=/workspace/probe bs=1048576 count=1 2>/dev/null; echo ready > /workspace/ready; sleep 30"}, Labels: labels}, HostConfig: &container.HostConfig{RestartPolicy: container.RestartPolicy{Name: "no"}, Runtime: "runc", CgroupnsMode: "private", NetworkMode: "none", IpcMode: "private", CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges=true"}, Resources: container.Resources{NanoCPUs: 250000000, Memory: 128 << 20, MemorySwap: 128 << 20, PidsLimit: &pids}, Mounts: []mount.Mount{{Type: mount.TypeBind, Source: filepath.Join(directory, "workspace"), Target: "/workspace", BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate}}}, LogConfig: container.LogConfig{Type: "local", Config: map[string]string{"max-size": "1m", "max-file": "2"}}}}
	authority := journal.Authority{TenantID: scope.TenantID, HostID: scope.HostID, SessionEpoch: scope.SessionEpoch, EndpointIdentity: scope.EndpointIdentity, KeyID: "fixture"}
	object, err := engine.Ensure(ctx, plan, func() error { return s.ClaimCreation(ctx, start, authority) })
	if err != nil {
		t.Fatal(err)
	}
	event := func(sequence uint64, state string) []byte {
		v := storetest.Object(t, storetest.Event(t, start, sequence, state))
		ref := v["observation"].(map[string]any)["runtimeRef"].(map[string]any)
		ref["scope"] = scope.EndpointIdentity
		ref["resourceId"] = object.ID
		return storetest.Encode(t, "HostEvent", v)
	}
	if err = s.RecordObservation(ctx, scope, event(1, "prepared")); err != nil {
		t.Fatal(err)
	}
	object, err = engine.Start(ctx, object.ID, plan, func() error { return s.VerifyCreationClaim(ctx, scope, start) })
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RecordObservation(ctx, scope, event(2, "running")); err != nil {
		t.Fatal(err)
	}
	// Configuration security/resource limits remain exact; quotas are absent.
	if _, err = engine.Inspect(ctx, object.ID, plan); err != nil {
		t.Fatal(err)
	}
	sampler := &telemetry.Sampler{Paths: []string{state, storage}}
	first := sampler.Collect(ctx, scope.EndpointIdentity, reader, []telemetry.Target{{ExecutionID: identity.ExecutionID, Generation: identity.Generation, ResourceID: object.ID}}, true)
	time.Sleep(150 * time.Millisecond)
	sample := sampler.Collect(ctx, scope.EndpointIdentity, reader, []telemetry.Target{{ExecutionID: identity.ExecutionID, Generation: identity.Generation, ResourceID: object.ID}}, true)
	raw, _ = json.MarshalIndent(sample, "", "  ")
	if err = protocol.ValidateInboundJSON("ResourceTelemetry", raw); err != nil {
		t.Fatal(err)
	}
	if first.CPU.UtilizationBasisPoints != nil || sample.CPU.Status != "available" || sample.Memory.Status != "available" || sample.Docker.Status != "available" || len(sample.Executions) != 1 || sample.Executions[0].MemoryUsageBytes == nil {
		t.Fatal("actual observations unavailable", string(raw))
	}
	if !sample.ExecutionsComplete {
		t.Fatal("verified original sample incomplete")
	}
	if err = os.WriteFile(filepath.Join(root, "sample.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	// This diagnostic helper can observe any threshold; the execution controller
	// no longer invokes it. Even an impossible threshold is not storage policy.
	if err = reader.CheckHeadroom(ctx, ^uint64(0)); err == nil {
		t.Fatal("diagnostic fixture threshold should exceed actual free space")
	}
	if err = s.RequireCleanup(ctx, scope, event(3, "cleanup-pending")); err != nil {
		t.Fatal(err)
	}
	if err = engine.Stop(ctx, object.ID, plan); err != nil {
		t.Fatal(err)
	}
	if err = engine.Remove(ctx, object.ID, plan); err != nil {
		t.Fatal(err)
	}
	if _, err = engine.Inspect(ctx, object.ID, plan); !errors.Is(err, dockerengine.ErrAbsent) {
		t.Fatal(err)
	}
	if err = reader.VerifyStorageReleased(ctx, object.ID, plan); err != nil {
		t.Fatal(err)
	}
	if err = manager.Dispose(ctx, identity); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatal("owned workspace remains", err)
	}
	storetest.Reconcile(t, s, scope, "2", agent.Watermark{ExecutionID: identity.ExecutionID, Generation: identity.Generation, ContiguousSequence: "0"})
	cleaned := event(4, "cleaned")
	proof := storetest.Proof(t, cleaned, "2")
	proof.EndpointIdentity = scope.EndpointIdentity
	if err = s.CompleteCleanup(ctx, scope, cleaned, proof); err != nil {
		t.Fatal(err)
	}
	summary := map[string]any{"sharedFilesystem": true, "filesystemType": fs.Type, "quotaConfigured": len(plan.HostConfig.StorageOpt) != 0, "containerRemoved": true, "workspaceDisposed": true, "cpuLimitNanoCPUs": plan.HostConfig.NanoCPUs, "memoryLimitBytes": plan.HostConfig.Memory, "pidLimit": pids, "host": host, "productionActivated": false}
	raw, _ = json.MarshalIndent(summary, "", "  ")
	os.WriteFile(filepath.Join(root, "result.json"), raw, 0600)
	t.Log(string(raw))
}
