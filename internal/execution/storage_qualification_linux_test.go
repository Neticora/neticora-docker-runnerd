//go:build linux && runnerd_storage_qualification

package execution

// Synthetic platform/image fixtures; real production controller, SQLite journal,
// protected Docker transport and filesystem lifecycle. Never provider evidence.
import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/executionstorage"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

const storageLab = "/var/lib/neticora-cleanup-lab-20261115"

type physicalRemote struct {
	*fakeRemote
	scope         agent.StoreScope
	commands      []protocol.StartCommand
	inventoryFile string
}

func (r *physicalRemote) Recovery(context.Context, []agent.ExecutionCursor) (protocol.RecoveryState, error) {
	entries := []protocol.RecoveryEntry{}
	for _, s := range r.commands {
		entries = append(entries, protocol.RecoveryEntry{ExecutionId: s.Spec.ExecutionId, Generation: s.Generation, CommandId: s.CommandId, SpecHash: s.Spec.SpecHash, ContiguousSequence: "0"})
	}
	return protocol.RecoveryState{Identity: protocol.HostIdentity{HostId: r.scope.HostID, KeyId: "key-a", KeyVersion: "1", SessionEpoch: "1"}, EndpointIdentity: r.scope.EndpointIdentity, InventoryGeneration: r.inventory, Entries: entries}, nil
}

func (r *physicalRemote) Inventory(ctx context.Context, message protocol.Outbound) error {
	var snapshot protocol.InventorySnapshot
	if json.Unmarshal(message.Bytes(), &snapshot) != nil {
		return ErrReconcile
	}
	previous, err := strconv.ParseUint(r.inventory, 10, 64)
	if err != nil || snapshot.InventoryGeneration != strconv.FormatUint(previous+1, 10) {
		return ErrReconcile
	}
	if err = r.fakeRemote.Inventory(ctx, message); err != nil {
		return err
	}
	file, err := os.OpenFile(r.inventoryFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write([]byte(r.inventory))
	if err == nil {
		err = file.Sync()
	}
	file.Close()
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(r.inventoryFile))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

type physicalRuntime struct {
	*dockerengine.Engine
	loseCreate, loseStart bool
	loseRemove            bool
	ensures, starts       int
}

func (r *physicalRuntime) Ensure(ctx context.Context, p dockerengine.Plan, claim func() error) (dockerengine.Object, error) {
	r.ensures++
	o, err := r.Engine.Ensure(ctx, p, claim)
	if err == nil && r.loseCreate {
		r.loseCreate = false
		return dockerengine.Object{}, dockerengine.ErrUnavailable
	}
	return o, err
}
func (r *physicalRuntime) Start(ctx context.Context, id string, p dockerengine.Plan, auth func() error) (dockerengine.Object, error) {
	r.starts++
	o, err := r.Engine.Start(ctx, id, p, auth)
	if err == nil && r.loseStart {
		r.loseStart = false
		return dockerengine.Object{}, dockerengine.ErrUnavailable
	}
	return o, err
}
func (r *physicalRuntime) Remove(ctx context.Context, id string, p dockerengine.Plan) error {
	if err := r.Engine.Remove(ctx, id, p); err != nil {
		return err
	}
	if r.loseRemove {
		r.loseRemove = false
		return dockerengine.ErrUnavailable
	}
	return nil
}

type physicalFixture struct {
	c       *Controller
	runtime *physicalRuntime
	remote  *physicalRemote
	base    string
	options journal.Options
}

func physicalAction(t *testing.T, action, path string) {
	t.Helper()
	dir := os.Getenv("RUNNERD08_STORAGE_CONTROL")
	if !strings.HasPrefix(dir, storageLab+"/") {
		t.Fatal("explicit control directory required")
	}
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	raw, _ := json.Marshal(map[string]string{"action": action, "path": path, "id": id})
	tmp := filepath.Join(dir, id+".tmp")
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, id+".request.json")); err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(45 * time.Second)
	for time.Now().Before(end) {
		b, err := os.ReadFile(filepath.Join(dir, id+".reply.json"))
		if err == nil {
			var reply struct {
				OK    bool
				Error string
			}
			if json.Unmarshal(b, &reply) != nil || !reply.OK {
				t.Fatalf("lab action %s: %s", action, b)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("lab action timed out", action)
}
func newPhysical(t *testing.T, name string, small bool) *physicalFixture {
	return openPhysical(t, name, small, false)
}
func openPhysical(t *testing.T, name string, small, resume bool) *physicalFixture {
	t.Helper()
	host, _ := os.Hostname()
	if host != "runnerd08-storage-s0" || os.Geteuid() != 10001 || os.Getenv("RUNNERD08_STORAGE_RUN") == "" {
		t.Fatal("explicit disposable nonroot S0 lab required")
	}
	run := os.Getenv("RUNNERD08_STORAGE_RUN")
	if filepath.Base(run) != run {
		t.Fatal("invalid run")
	}
	base := filepath.Join(storageLab, run, name)
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	mk := func(p string) string {
		if err := os.Mkdir(p, 0700); err != nil && !(resume && os.IsExist(err)) {
			t.Fatal("retain original attempt; use fresh run id", err)
		}
		return p
	}
	bootstrapParent := filepath.Join("/run/neticora-cleanup-lab-20261115", run)
	os.MkdirAll(bootstrapParent, 0700)
	storageParent := filepath.Join("/mnt/s0-jobdata/cleanup-executions-20261115", run)
	if small {
		storageParent = filepath.Join("/mnt/cleanup-enospc-20261115", run)
	}
	os.MkdirAll(storageParent, 0700)
	storage := mk(filepath.Join(storageParent, name))
	state := mk(filepath.Join(base, "journal"))
	keys := mk(filepath.Join(base, "keys"))
	bootstrap := mk(filepath.Join(bootstrapParent, name))
	var image struct{ Repository, Digest, Network string }
	raw, err := os.ReadFile(filepath.Join(storageLab, "image.json"))
	if err != nil || json.Unmarshal(raw, &image) != nil {
		t.Fatal("immutable lab image required", err)
	}
	ctx := context.Background()
	scope := storetest.Scope
	scope.InstallationID = "cleanup-lab-" + run + "-" + name
	options := journal.Options{ReservationLimits: agent.ReservationLimits{CPUMillis: 2000, MemoryBytes: 2 << 30, StorageBytes: 20 << 30, Slots: 2}}
	s, err := journal.OpenRecovery(ctx, state, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	e, err := dockerengine.Open("unix:///run/docker.sock", scope.InstallationID, func() { _ = s.InvalidateRuntime(context.Background()) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	scope.EndpointIdentity, err = e.Probe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !resume {
		storetest.Reconcile(t, s, scope, "1")
	}
	policyJSON, err := os.ReadFile(filepath.Join(storageLab, "validation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		ID    string          `json:"id"`
		Value json.RawMessage `json:"value"`
	}
	json.Unmarshal(policyJSON, &fixtures)
	var policy *standardlinux.Policy
	for _, f := range fixtures {
		if f.ID == "customer-managed-policy-1.1" {
			var v map[string]any
			json.Unmarshal(f.Value, &v)
			v["restrictions"].(map[string]any)["runnerUid"] = 10001
			v["images"].(map[string]any)["allowedDigests"] = []string{image.Digest}
			v["maxConcurrentExecutions"] = "2"
			v["limits"].(map[string]any)["slots"] = "2"
			b, _ := json.Marshal(v)
			policy, err = standardlinux.ParsePolicy(b, nil)
		}
	}
	if policy == nil || err != nil {
		t.Fatal("fixture policy", err)
	}
	r := &physicalRuntime{Engine: e}
	counterFile := filepath.Join(base, "fixture-platform-inventory")
	inventory := "1"
	if resume {
		counter, err := os.ReadFile(counterFile)
		if err != nil {
			t.Fatal("original fixture platform counter required", err)
		}
		inventory = string(counter)
	}
	remote := &physicalRemote{fakeRemote: &fakeRemote{t: t, inventory: inventory}, scope: scope, inventoryFile: counterFile}
	c := &Controller{Store: s, Runtime: r, Remote: remote, Scope: scope, Authority: journal.Authority{TenantID: scope.TenantID, HostID: scope.HostID, SessionEpoch: scope.SessionEpoch, EndpointIdentity: scope.EndpointIdentity, KeyID: "key-a"}, Profile: standardlinux.Settings{ImageRepository: image.Repository, NetworkID: image.Network, StorageRoot: storage, BootstrapRoot: bootstrap, RunnerUID: 10001, PidsLimit: 64}, Policy: func() *standardlinux.Policy { return policy }, VerifyImage: func(context.Context, *standardlinux.Policy, string, string, time.Time) error { return nil }, KeysDirectory: keys, Organization: "Neticora", Repository: "Neticora/" + name, Pool: "pool-a", Drained: func() bool { return false }, MinRuntimeFreeBytes: 64 << 20, RuntimeStoragePaths: []string{"/mnt/s0-cache/cleanup-docker-20261115", "/mnt/s0-cache/cleanup-containerd-20261115"}, cancelled: map[agent.ExecutionCursor]bool{}}
	if resume {
		rows, err := s.Incomplete(ctx, agent.ExecutionCursor{}, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range rows {
			var command protocol.StartCommand
			if json.Unmarshal(e.Command, &command) != nil {
				t.Fatal("stored command")
			}
			remote.commands = append(remote.commands, command)
		}
		if _, err = c.refresh(ctx); err != nil {
			t.Fatal("original recovery", err)
		}
	}
	return &physicalFixture{c: c, runtime: r, remote: remote, base: base, options: options}
}
func (f *physicalFixture) accept(t *testing.T, name string) agent.Execution {
	t.Helper()
	v := storetest.Object(t, storetest.Start(t, name))
	spec := v["spec"].(map[string]any)
	spec["templateVersion"] = standardlinux.DiskTemplateVersion
	var image struct{ Digest string }
	b, _ := os.ReadFile(filepath.Join(storageLab, "image.json"))
	json.Unmarshal(b, &image)
	spec["imageDigest"] = image.Digest
	spec["resources"] = map[string]any{"cpuMillis": "250", "memoryBytes": "134217728", "storageBytes": "134217728", "slots": "1"}
	raw := storetest.Encode(t, "HostCommand", v)
	var command protocol.StartCommand
	json.Unmarshal(raw, &command)
	if _, err := f.c.accept(context.Background(), raw); err != nil {
		t.Fatal("admission", err)
	}
	f.remote.commands = append(f.remote.commands, command)
	return f.row(t, command.Spec.ExecutionId)
}
func (f *physicalFixture) row(t *testing.T, id string) agent.Execution {
	t.Helper()
	rows, err := f.c.Store.Executions(context.Background(), agent.ExecutionCursor{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rows {
		if e.Identity.ExecutionID == id {
			return e
		}
	}
	t.Fatal("original row missing")
	return agent.Execution{}
}
func (f *physicalFixture) path(t *testing.T, e agent.Execution) string {
	t.Helper()
	r, err := f.c.storage().Record(context.Background(), e.Identity)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(r.Root, r.Name)
}
func (f *physicalFixture) launch(t *testing.T, e agent.Execution) agent.Execution {
	t.Helper()
	if err := f.c.execution(context.Background(), e); err != nil {
		t.Fatal("production launch", err)
	}
	e = f.row(t, e.Identity.ExecutionID)
	p, _ := f.c.plan(e)
	o, err := f.runtime.Inspect(context.Background(), p.Name, p)
	if err != nil || o.ID == "" {
		t.Fatal("original Docker object", err)
	}
	physicalAction(t, "snapshot", o.ID)
	return e
}
func (f *physicalFixture) exited(t *testing.T, e agent.Execution, code int) agent.Execution {
	t.Helper()
	p, _ := f.c.plan(e)
	end := time.Now().Add(20 * time.Second)
	for time.Now().Before(end) {
		o, err := f.runtime.Inspect(context.Background(), p.Name, p)
		if err != nil {
			t.Fatal(err)
		}
		if o.State == "exited" {
			if o.ExitCode != code {
				t.Fatal("unexpected exit", o)
			}
			if err = f.c.execution(context.Background(), f.row(t, e.Identity.ExecutionID)); err != nil {
				t.Fatal("exit observation", err)
			}
			return f.row(t, e.Identity.ExecutionID)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("bounded job timeout")
	return e
}
func (f *physicalFixture) control(t *testing.T, e agent.Execution, kind string) {
	t.Helper()
	raw := storetest.Encode(t, "HostCommand", map[string]any{"commandId": kind + "-" + e.Identity.ExecutionID, "kind": kind, "executionId": e.Identity.ExecutionID, "generation": e.Identity.Generation})
	if _, err := f.c.accept(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
}
func (f *physicalFixture) reserved(t *testing.T, e agent.Execution, want bool) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(f.base, "journal", "journal.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var released bool
	if err = db.QueryRow("SELECT released FROM reservations WHERE execution_id=? AND generation=?", e.Identity.ExecutionID, e.Identity.Generation).Scan(&released); err != nil || released == want {
		t.Fatal("reservation ordering", released, want, err)
	}
}
func (f *physicalFixture) clean(t *testing.T, e agent.Execution) {
	t.Helper()
	path := f.path(t, e)
	f.reserved(t, e, true)
	f.control(t, e, "cleanup")
	if err := f.c.execution(context.Background(), f.row(t, e.Identity.ExecutionID)); err != nil {
		t.Fatal("cleanup", err)
	}
	e = f.row(t, e.Identity.ExecutionID)
	if e.State != "cleaned" {
		t.Fatal("not cleaned", e.State)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("workspace remains", err)
	}
	f.reserved(t, e, false)
	r, err := f.c.storage().Record(context.Background(), e.Identity)
	if err != nil || r.State != "disposed" {
		t.Fatal("disposal evidence missing", err)
	}
	physicalAction(t, "record", f.base)
}
func TestRunnerd08StoragePhysical(t *testing.T) {
	for _, name := range []string{"success", "failure", "timeout"} {
		t.Run(name, func(t *testing.T) {
			f := newPhysical(t, name, false)
			e := f.launch(t, f.accept(t, name))
			if name == "timeout" {
				time.Sleep(time.Second)
				f.control(t, e, "cancel")
				f.clean(t, e)
				return
			}
			code := 0
			if name == "failure" {
				code = 17
			}
			e = f.exited(t, e, code)
			if _, err := os.Stat(filepath.Join(f.path(t, e), "diagnostics", "delivery")); err != nil {
				t.Fatal("required fixture poststeps incomplete", err)
			}
			f.clean(t, e)
		})
	}
	t.Run("parallel", func(t *testing.T) {
		f := newPhysical(t, "parallel", false)
		a := f.launch(t, f.accept(t, "parallel-a"))
		b := f.launch(t, f.accept(t, "parallel-b"))
		pa, pb := f.path(t, a), f.path(t, b)
		if pa == pb {
			t.Fatal("shared storage")
		}
		if err := os.WriteFile(filepath.Join(pa, "workspace", "finish"), []byte("done"), 0600); err != nil {
			t.Fatal(err)
		}
		a = f.exited(t, a, 0)
		f.clean(t, a)
		if _, err := os.Stat(filepath.Join(pb, "workspace", "ready")); err != nil {
			t.Fatal("cross-deletion", err)
		}
		os.WriteFile(filepath.Join(pb, "workspace", "finish"), []byte("done"), 0600)
		b = f.exited(t, b, 0)
		f.clean(t, b)
	})
	t.Run("lost-remove-response", func(t *testing.T) {
		f := newPhysical(t, "lost-remove-response", false)
		e := f.launch(t, f.accept(t, "lost-remove"))
		e = f.exited(t, e, 0)
		path := f.path(t, e)
		before, _ := f.c.storage().Record(context.Background(), e.Identity)
		f.control(t, e, "cleanup")
		f.runtime.loseRemove = true
		if err := f.c.execution(context.Background(), e); !errors.Is(err, dockerengine.ErrUnavailable) {
			t.Fatal(err)
		}
		f.reserved(t, e, true)
		if _, err := os.Stat(path); err != nil {
			t.Fatal("lost response destroyed storage", err)
		}
		if err := f.c.execution(context.Background(), f.row(t, e.Identity.ExecutionID)); err != nil {
			t.Fatal(err)
		}
		after, _ := f.c.storage().Record(context.Background(), e.Identity)
		if before.DirectoryIdentity != after.DirectoryIdentity || after.State != "disposed" || f.runtime.ensures != 1 || f.runtime.starts != 1 {
			t.Fatal("response loss replaced original", after)
		}
		f.reserved(t, e, false)
		physicalAction(t, "record", f.base)
	})
	t.Run("restricted-owner", func(t *testing.T) {
		f := newPhysical(t, "restricted-owner", false)
		e := f.launch(t, f.accept(t, "restricted"))
		e = f.exited(t, e, 0)
		path := f.path(t, e)
		file := filepath.Join(path, "workspace", "root-owned")
		os.WriteFile(file, []byte("retain"), 0600)
		physicalAction(t, "root-owner", file)
		f.control(t, e, "cleanup")
		if err := f.c.execution(context.Background(), e); !errors.Is(err, executionstorage.ErrQuarantined) {
			t.Fatal("unsafe ownership cleanup", err)
		}
		f.reserved(t, e, true)
		r, _ := f.c.storage().Record(context.Background(), e.Identity)
		if r.State == "disposed" {
			t.Fatal("false disposal")
		}
		physicalAction(t, "record", f.base)
	})
	t.Run("mount-crossing", func(t *testing.T) {
		f := newPhysical(t, "mount-crossing", false)
		e := f.launch(t, f.accept(t, "mount"))
		e = f.exited(t, e, 0)
		path := filepath.Join(f.path(t, e), "workspace", "mount-crossing")
		os.Mkdir(path, 0700)
		physicalAction(t, "bind-mount", path)
		f.control(t, e, "cleanup")
		if err := f.c.execution(context.Background(), e); err == nil {
			t.Fatal("live mount retired")
		}
		f.reserved(t, e, true)
		physicalAction(t, "record", f.base)
	})
	t.Run("unknown-directory", func(t *testing.T) {
		f := newPhysical(t, "unknown-directory", false)
		e := f.accept(t, "unknown")
		os.Mkdir(filepath.Join(f.c.Profile.StorageRoot, "unknown"), 0700)
		if _, err := f.c.refresh(context.Background()); !errors.Is(err, executionstorage.ErrQuarantined) {
			t.Fatal("unknown root accepted", err)
		}
		f.reserved(t, e, true)
		physicalAction(t, "record", f.base)
	})
	t.Run("enospc", func(t *testing.T) {
		f := newPhysical(t, "enospc", true)
		e := f.launch(t, f.accept(t, "enospc"))
		e = f.exited(t, e, 0)
		fill, err := os.OpenFile("/mnt/cleanup-enospc-20261115/owned-filler", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 1<<20)
		var written int
		for written < 128<<20 {
			n, e := fill.Write(buffer)
			written += n
			if e != nil {
				if !errors.Is(e, os.ErrInvalid) && !strings.Contains(e.Error(), "no space left") {
					t.Fatal(e)
				}
				break
			}
		}
		fill.Sync()
		fill.Close()
		if written >= 128<<20 {
			t.Fatal("not bounded physical exhaustion")
		}
		if err = f.c.runtimeHeadroom(context.Background()); err == nil {
			t.Fatal("disk-full admission open")
		}
		f.clean(t, e)
		t.Log("physical ENOSPC bytes", written)
	})
	t.Run("process-restart", func(t *testing.T) {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child := exec.Command(executable, "-test.run=^TestRunnerd08StorageProcessChild$", "-test.v")
		child.Env = append(os.Environ(), "RUNNERD08_STORAGE_CHILD=1")
		logPath := filepath.Join(storageLab, os.Getenv("RUNNERD08_STORAGE_RUN"), "process-child.log")
		log, err := os.Create(logPath)
		if err != nil {
			t.Fatal(err)
		}
		defer log.Close()
		child.Stdout = log
		child.Stderr = log
		if err = child.Start(); err != nil {
			t.Fatal(err)
		}
		defer child.Process.Kill()
		marker := filepath.Join(storageLab, os.Getenv("RUNNERD08_STORAGE_RUN"), "process-restart-hold", "ready.json")
		deadline := time.Now().Add(30 * time.Second)
		for {
			if _, err = os.Stat(marker); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("child did not launch")
			}
			time.Sleep(50 * time.Millisecond)
		}
		var before struct {
			Execution agent.Execution
			Storage   journal.ExecutionStorage
		}
		raw, _ := os.ReadFile(marker)
		if json.Unmarshal(raw, &before) != nil {
			t.Fatal("child state")
		}
		if err = child.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		child.Wait()
		f := openPhysical(t, "process-restart-hold", false, true)
		e := f.row(t, before.Execution.Identity.ExecutionID)
		after, err := f.c.storage().Record(context.Background(), e.Identity)
		if err != nil || after != before.Storage || string(e.RuntimeRef) != string(before.Execution.RuntimeRef) {
			t.Fatal("process crash changed ownership", err)
		}
		os.WriteFile(filepath.Join(f.path(t, e), "workspace", "finish"), []byte("done"), 0600)
		e = f.exited(t, e, 0)
		f.clean(t, e)
		if f.runtime.ensures != 0 || f.runtime.starts != 0 {
			t.Fatal("process restart replaced/restarted original")
		}
	})
	t.Run("docker-restart-fence", func(t *testing.T) {
		f := newPhysical(t, "docker-restart-hold", false)
		e := f.launch(t, f.accept(t, "docker-restart"))
		before, _ := f.c.storage().Record(context.Background(), e.Identity)
		ref := string(e.RuntimeRef)
		physicalAction(t, "restart-docker", "")
		if err := f.c.execution(context.Background(), e); err == nil {
			t.Fatal("replacement endpoint accepted")
		}
		after, _ := f.c.storage().Record(context.Background(), e.Identity)
		if after != before || string(f.row(t, e.Identity.ExecutionID).RuntimeRef) != ref {
			t.Fatal("restart changed original ownership")
		}
		f.reserved(t, e, true)
		physicalAction(t, "record", f.base)
	})
}

func TestRunnerd08StorageProcessChild(t *testing.T) {
	if os.Getenv("RUNNERD08_STORAGE_CHILD") != "1" {
		t.Skip("child only")
	}
	name := "process-restart-hold"
	if os.Getenv("RUNNERD08_STORAGE_RETIRE") == "1" {
		name = "retirement-restart"
	}
	f := newPhysical(t, name, false)
	e := f.launch(t, f.accept(t, name))
	if os.Getenv("RUNNERD08_STORAGE_RETIRE") == "1" {
		os.WriteFile(filepath.Join(f.path(t, e), "workspace", "finish"), []byte("done"), 0600)
		e = f.exited(t, e, 0)
		restricted := filepath.Join(f.path(t, e), "workspace", "restricted")
		os.Mkdir(restricted, 0700)
		os.WriteFile(filepath.Join(restricted, "retained"), []byte("owner repair required"), 0600)
		os.Chmod(restricted, 0000)
		f.control(t, e, "cleanup")
		if err := f.c.execution(context.Background(), e); !errors.Is(err, executionstorage.ErrQuarantined) {
			t.Fatal("retirement did not stop", err)
		}
		e = f.row(t, e.Identity.ExecutionID)
	}
	storage, err := f.c.storage().Record(context.Background(), e.Identity)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"Execution": e, "Storage": storage})
	if err = os.WriteFile(filepath.Join(f.base, "ready.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Second)
	}
}

func TestRunnerd08StorageAdditional(t *testing.T) {
	t.Run("lost-create-response", func(t *testing.T) {
		f := newPhysical(t, "lost-create", false)
		e := f.accept(t, "lost-create")
		f.runtime.loseCreate = true
		if err := f.c.execution(context.Background(), e); !errors.Is(err, dockerengine.ErrUnavailable) {
			t.Fatal(err)
		}
		p, _ := f.c.plan(e)
		original, err := f.runtime.Inspect(context.Background(), p.Name, p)
		if err != nil {
			t.Fatal(err)
		}
		before, _ := f.c.storage().Record(context.Background(), e.Identity)
		for i := 0; i < 2; i++ {
			if err = f.c.execution(context.Background(), f.row(t, e.Identity.ExecutionID)); err != nil {
				t.Fatal("original create recovery", err)
			}
		}
		after, _ := f.c.storage().Record(context.Background(), e.Identity)
		observed, err := f.runtime.Inspect(context.Background(), p.Name, p)
		if err != nil || observed.ID != original.ID || before != after || f.runtime.starts != 1 {
			t.Fatal("create response loss replaced ownership", err)
		}
		e = f.exited(t, f.row(t, e.Identity.ExecutionID), 0)
		f.clean(t, e)
	})
	t.Run("lost-start-response", func(t *testing.T) {
		f := newPhysical(t, "lost-start-hold", false)
		e := f.accept(t, "lost-start")
		f.runtime.loseStart = true
		if err := f.c.execution(context.Background(), e); !errors.Is(err, dockerengine.ErrUnavailable) {
			t.Fatal(err)
		}
		e = f.row(t, e.Identity.ExecutionID)
		ref := string(e.RuntimeRef)
		if err := f.c.execution(context.Background(), e); err != nil {
			t.Fatal(err)
		}
		e = f.row(t, e.Identity.ExecutionID)
		if string(e.RuntimeRef) != ref || f.runtime.starts != 1 || f.runtime.ensures != 1 {
			t.Fatal("start replay replaced original")
		}
		os.WriteFile(filepath.Join(f.path(t, e), "workspace", "finish"), []byte("done"), 0600)
		e = f.exited(t, e, 0)
		f.clean(t, e)
	})
	t.Run("symlink", func(t *testing.T) {
		f := newPhysical(t, "symlink", false)
		e := f.launch(t, f.accept(t, "symlink"))
		e = f.exited(t, e, 0)
		canary := filepath.Join(f.base, "outside-canary")
		os.WriteFile(canary, []byte("retain outside execution"), 0600)
		if err := os.Symlink(canary, filepath.Join(f.path(t, e), "workspace", "escape")); err != nil {
			t.Fatal(err)
		}
		f.clean(t, e)
		if b, err := os.ReadFile(canary); err != nil || string(b) != "retain outside execution" {
			t.Fatal("symlink escaped root", err)
		}
	})
	t.Run("unknown-container", func(t *testing.T) {
		f := newPhysical(t, "unknown-container", false)
		e := f.accept(t, "unknown-container")
		physicalAction(t, "unknown-container", f.c.Scope.InstallationID)
		if _, err := f.c.refresh(context.Background()); err == nil {
			t.Fatal("unknown container accepted")
		}
		f.reserved(t, e, true)
		physicalAction(t, "record", f.base)
	})
	t.Run("restricted-permissions", func(t *testing.T) {
		f := newPhysical(t, "restricted-permissions", false)
		e := f.launch(t, f.accept(t, "restricted-permissions"))
		e = f.exited(t, e, 0)
		path := filepath.Join(f.path(t, e), "workspace", "restricted")
		os.Mkdir(path, 0700)
		os.WriteFile(filepath.Join(path, "keep"), []byte("retain"), 0600)
		os.Chmod(path, 0000)
		f.control(t, e, "cleanup")
		if err := f.c.execution(context.Background(), e); !errors.Is(err, executionstorage.ErrQuarantined) {
			t.Fatal("permissions bypassed", err)
		}
		f.reserved(t, e, true)
		physicalAction(t, "record", f.base)
	})
	t.Run("interrupted-retirement", func(t *testing.T) {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child := exec.Command(executable, "-test.run=^TestRunnerd08StorageProcessChild$", "-test.v")
		child.Env = append(os.Environ(), "RUNNERD08_STORAGE_CHILD=1", "RUNNERD08_STORAGE_RETIRE=1")
		log, _ := os.Create(filepath.Join(storageLab, os.Getenv("RUNNERD08_STORAGE_RUN"), "retirement-child.log"))
		defer log.Close()
		child.Stdout = log
		child.Stderr = log
		if err = child.Start(); err != nil {
			t.Fatal(err)
		}
		defer child.Process.Kill()
		marker := filepath.Join(storageLab, os.Getenv("RUNNERD08_STORAGE_RUN"), "retirement-restart", "ready.json")
		deadline := time.Now().Add(30 * time.Second)
		for {
			if _, err = os.Stat(marker); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("retirement child not ready")
			}
			time.Sleep(50 * time.Millisecond)
		}
		var before struct {
			Execution agent.Execution
			Storage   journal.ExecutionStorage
		}
		raw, _ := os.ReadFile(marker)
		json.Unmarshal(raw, &before)
		if before.Storage.State != "retiring" {
			t.Fatal("not partial retirement")
		}
		child.Process.Kill()
		child.Wait()
		f := openPhysical(t, "retirement-restart", false, true)
		e := f.row(t, before.Execution.Identity.ExecutionID)
		after, err := f.c.storage().Record(context.Background(), e.Identity)
		if err != nil || after != before.Storage || string(e.RuntimeRef) != string(before.Execution.RuntimeRef) {
			t.Fatal("retirement lost original", err)
		}
		f.reserved(t, e, true)
		if err = os.Chmod(filepath.Join(f.path(t, e), "workspace", "restricted"), 0700); err != nil {
			t.Fatal(err)
		}
		f.clean(t, e)
		if f.runtime.ensures != 0 || f.runtime.starts != 0 {
			t.Fatal("retirement allocated replacement")
		}
	})
	t.Run("inode-exhaustion", func(t *testing.T) {
		// Reuse only the explicitly owned zero-filled probe file, not a job directory
		// or quarantined resource. Its prior ENOSPC witness remains in run-002.
		filler, err := os.OpenFile("/mnt/cleanup-enospc-20261115/owned-filler", os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err = filler.Truncate(0); err != nil {
			t.Fatal(err)
		}
		filler.Sync()
		filler.Close()
		f := newPhysical(t, "inodes", true)
		directory := "/mnt/cleanup-enospc-20261115/inode-probe"
		if err = os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		count := 0
		for ; count < 8192; count++ {
			file, e := os.OpenFile(filepath.Join(directory, fmt.Sprint(count)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				if !strings.Contains(e.Error(), "no space left") {
					t.Fatal(e)
				}
				break
			}
			file.Close()
		}
		if count == 8192 {
			t.Fatal("inode limit not reached")
		}
		if err = f.c.runtimeHeadroom(context.Background()); err == nil {
			t.Fatal("inode exhaustion admitted new work")
		}
		physicalAction(t, "record", f.base)
		t.Log("physical inode exhaustion files", count)
	})
}
