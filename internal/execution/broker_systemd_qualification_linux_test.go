//go:build linux && runnerd_broker_qualification

package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/broker"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

// The multiplexer keeps distinct execution authority under one installation,
// issuer, physical ledger and broker socket. It is a protocol/provider fixture.
func phaseD2AuthorityMux(fixtures []*phaseDAuthority) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(fixtures) == 1 {
			fixtures[0].ServeHTTP(w, r)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil || len(raw) > 65536 {
			w.WriteHeader(400)
			return
		}
		var envelope struct {
			ExecutionID string `json:"executionId"`
			Request     struct {
				ExecutionID string `json:"executionId"`
			} `json:"request"`
			Events []struct {
				ExecutionID string `json:"executionId"`
			} `json:"events"`
			Challenge json.RawMessage `json:"challenge"`
		}
		if json.Unmarshal(raw, &envelope) != nil {
			w.WriteHeader(400)
			return
		}
		id := envelope.ExecutionID
		if id == "" {
			id = envelope.Request.ExecutionID
		}
		if id == "" && len(envelope.Events) > 0 {
			id = envelope.Events[0].ExecutionID
			for _, e := range envelope.Events {
				if e.ExecutionID != id {
					w.WriteHeader(400)
					return
				}
			}
		}
		if id == "" {
			var signed struct {
				Challenge struct {
					Binding struct {
						ExecutionID string `json:"executionId"`
					} `json:"binding"`
				} `json:"challenge"`
			}
			if json.Unmarshal(envelope.Challenge, &signed) != nil {
				w.WriteHeader(400)
				return
			}
			id = signed.Challenge.Binding.ExecutionID
		}
		for _, f := range fixtures {
			if f.start.Spec.ExecutionId == id {
				r.Body = io.NopCloser(bytes.NewReader(raw))
				f.ServeHTTP(w, r)
				return
			}
		}
		w.WriteHeader(403)
	})
}

type phaseD2Services struct {
	base, state, broker string
	units               []string
	closing             sync.Once
}

func phaseD2Command(args ...string) ([]byte, error) {
	return exec.Command(args[0], args[1:]...).CombinedOutput()
}
func phaseD2InstallBroker(t *testing.T, base, state, config string) *phaseD2Services {
	t.Helper()
	binary := os.Getenv("RUNNERD_D2_BROKER_BINARY")
	info, err := os.Lstat(binary)
	if err != nil || !filepath.IsAbs(binary) || hostfs.CheckAncestors(filepath.Dir(binary)) != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		t.Fatal("root-protected qualification broker binary required", err)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 || !info.Mode().IsRegular() {
		t.Fatal("qualification broker binary must be root-owned regular file")
	}
	s := &phaseD2Services{base: base, state: state, broker: "neticora-d2-" + filepath.Base(base) + "-broker.service"}
	t.Cleanup(func() { s.close(t) })
	body := fmt.Sprintf(`[Unit]
Description=Neticora D2 disposable broker qualification
After=local-fs.target
StartLimitIntervalSec=20
StartLimitBurst=5
[Service]
Type=exec
User=root
Group=root
ExecStart=%s --config %s
Restart=on-failure
RestartSec=200ms
TimeoutStopSec=15s
KillMode=control-group
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=%s %s
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_SYS_PTRACE
FileDescriptorStoreMax=0
`, strconv.Quote(binary), strconv.Quote(config), base, state)
	body, err = phaseE2BrokerUnitFromConfig(body, config)
	if err != nil {
		t.Fatal("Kata broker service boundary", err)
	}
	s.install(t, s.broker, body)
	if output, err := phaseD2Command("systemctl", "start", s.broker); err != nil {
		journal, _ := phaseD2Command("journalctl", "--unit", s.broker, "--no-pager", "-o", "cat", "-n", "60")
		details, _ := phaseD2Command("systemctl", "show", s.broker, "-p", "Result", "-p", "ExecMainStatus", "-p", "NRestarts")
		trace := append(append(output, journal...), details...)
		phaseDWrite(t, filepath.Join(state, s.broker+".startup.log"), trace, 0600, 0)
		t.Fatalf("installed broker start: %v %s", err, trace)
	}
	t.Log("installed qualification broker", s.broker)
	return s
}
func (s *phaseD2Services) install(t *testing.T, name, body string) {
	t.Helper()
	path := filepath.Join("/etc/systemd/system", name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		t.Fatal(err)
	}
	s.units = append(s.units, name)
	_, err = f.WriteString(body)
	if err == nil {
		err = f.Sync()
	}
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	phaseDWrite(t, filepath.Join(s.state, name), []byte(body), 0600, 0)
	if output, err := phaseD2Command("systemctl", "daemon-reload"); err != nil {
		t.Fatalf("daemon reload: %v %s", err, output)
	}
}
func (s *phaseD2Services) controller(t *testing.T, self, publicPath string, p phaseDPublic, inherited bool) ([]byte, error) {
	t.Helper()
	suffix := "controller"
	extra := ""
	if masks, err := phaseE2ControllerPaths(p); err != nil {
		t.Fatal(err)
	} else {
		extra += masks
	}
	if inherited {
		suffix = "inherited"
		extra += "Environment=RUNNERD_PHASE_D_INHERITED=1\nOpenFile=" + strings.TrimPrefix(p.Endpoint, "unix://") + ":privileged-docker\n"
	}
	name := "neticora-d2-" + filepath.Base(s.base) + "-" + suffix + ".service"
	if p.CrashController && !inherited {
		extra += "Restart=on-failure\nRestartSec=200ms\n"
	}
	body := fmt.Sprintf(`[Unit]
Description=Neticora D2 installed controller qualification
After=%s
StartLimitIntervalSec=300
StartLimitBurst=2
[Service]
Type=oneshot
RemainAfterExit=yes
User=10002
Group=10002
SupplementaryGroups=
ExecStart=%s -test.run=^TestPhaseDControllerRealDocker$ -test.v
Environment=RUNNERD_PHASE_D_CHILD=%s
Environment=RUNNERD_D2_SYSTEMD=1
Environment=DOCKER_HOST=unix://%s/alternate.sock
Environment=TMPDIR=/var/tmp
%sTimeoutStartSec=120s
TimeoutStopSec=10s
KillMode=control-group
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=%s %s %s
InaccessiblePaths=-/run/docker.sock -/var/run/docker.sock -/run/containerd -/run/k3s/containerd -%s -%s/private -%s/broker -%s/alternate.sock
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=
AmbientCapabilities=
FileDescriptorStoreMax=0
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
`, s.broker, strconv.Quote(self), publicPath, s.base, extra, p.Source, p.Keys, p.State, strings.TrimPrefix(p.Endpoint, "unix://"), s.base, s.state, s.base)
	s.install(t, name, body)
	start, err := phaseD2Command("systemctl", "start", name)
	if err != nil && p.CrashController && !inherited {
		until := time.Now().Add(110 * time.Second)
		for time.Now().Before(until) {
			state, _ := phaseD2Command("systemctl", "show", name, "-p", "ActiveState", "--value")
			if strings.TrimSpace(string(state)) == "active" {
				err = nil
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	journal, _ := phaseD2Command("journalctl", "--unit", name, "--no-pager", "-o", "cat")
	audit, _ := phaseD2Command("systemctl", "show", name, "-p", "User", "-p", "Group", "-p", "NoNewPrivileges", "-p", "CapabilityBoundingSet", "-p", "FileDescriptorStoreMax", "-p", "KillMode", "-p", "ExecMainStatus", "-p", "InaccessiblePaths")
	output := append(append(start, journal...), audit...)
	if p.CrashController && !inherited {
		restarts, e := phaseD2Command("systemctl", "show", name, "-p", "NRestarts", "--value")
		if e != nil || strings.TrimSpace(string(restarts)) != "1" {
			return output, fmt.Errorf("controller restart count differs from one: %s", restarts)
		}
	}
	phaseDWrite(t, filepath.Join(s.state, name+".log"), output, 0600, 0)
	return output, err
}
func (s *phaseD2Services) close(t *testing.T) {
	s.closing.Do(func() {
		for i := len(s.units) - 1; i >= 0; i-- {
			name := s.units[i]
			_, _ = phaseD2Command("systemctl", "stop", name)
			_, _ = phaseD2Command("systemctl", "reset-failed", name)
			if err := os.Remove(filepath.Join("/etc/systemd/system", name)); err != nil {
				t.Error(err)
			}
		}
		_, _ = phaseD2Command("systemctl", "daemon-reload")
	})
}
func phaseD2CreatedExactly(t *testing.T, endpoint, installation string, since time.Time, fixtures []*phaseDAuthority) {
	t.Helper()
	docker := os.Getenv("RUNNERD_D2_DOCKER_BINARY")
	if docker == "" {
		docker = "/opt/neticora-runnerd-lab/docker-29.9.3/bin/docker"
	}
	output, err := phaseD2Command(docker, "-H", endpoint, "events", "--since", since.Add(-time.Second).Format(time.RFC3339Nano), "--until", time.Now().UTC().Format(time.RFC3339Nano), "--filter", "type=container", "--filter", "event=create", "--filter", "label=com.neticora.runnerd.installation="+installation, "--format", "{{.Actor.ID}}")
	if err != nil {
		t.Fatalf("Docker create witness unavailable: %v %s", err, output)
	}
	ids := strings.Fields(string(output))
	if len(ids) != len(fixtures) {
		t.Fatalf("physical create count %d, expected %d", len(ids), len(fixtures))
	}
	for _, f := range fixtures {
		found := false
		for _, id := range ids {
			if id == f.resource {
				found = true
			}
		}
		if !found {
			t.Fatal("original resource differs from Docker creation witness")
		}
	}
	t.Logf("Docker event witness: exactly %d original containers created", len(ids))
}

func phaseD2RunJobs(t *testing.T, ctx context.Context, c *Controller, p phaseDPublic, r *phaseDRemote) {
	t.Helper()
	current := func(startID string) agent.Execution {
		for _, start := range p.Starts {
			if start.Spec.ExecutionId == startID {
				e, err := c.Store.PeerRecoveryExecution(ctx, startID, start.Generation)
				if err != nil {
					t.Fatal(err)
				}
				return e
			}
		}
		t.Fatal("missing execution")
		return agent.Execution{}
	}
	stepUntil := func(id, want string) {
		last := ""
		for {
			e := current(id)
			if e.State == want {
				return
			}
			if err := c.execution(ctx, e); err != nil && err.Error() != last {
				last = err.Error()
				t.Logf("qualification reconciliation %s (%s): %v", id, e.State, err)
			}
			if ctx.Err() != nil {
				t.Fatalf("execution %s did not reach %s: %s", id, want, e.State)
			}
			time.Sleep(75 * time.Millisecond)
		}
	}
	if p.ExpectQuarantine {
		start := p.Starts[0]
		lookup := broker.Lookup{ExecutionID: start.Spec.ExecutionId, Generation: start.Generation, SpecHash: start.Spec.SpecHash}
		for {
			e := current(start.Spec.ExecutionId)
			_ = c.execution(ctx, e)
			response, _ := broker.Call(ctx, p.Socket, broker.Request{Version: broker.Version, Operation: "ReconcileExecution", Lookup: &lookup})
			if response.Runtime != nil && response.Runtime.Phase == "QUARANTINED" && response.Runtime.Object == nil {
				if err := c.Store.VerifyCreationClaim(ctx, c.Scope, e.Command); err != nil {
					t.Fatal(err)
				}
				if e.State == "cleaned" || response.Runtime.Operations["CreateExecution"].OperationID == "" {
					t.Fatal("unknown creation lost original ownership")
				}
				if ids, err := c.Runtime.Inventory(ctx); err != nil || len(ids) != p.ExpectedOwned {
					t.Fatal("unknown create repeated", ids, err)
				}
				t.Logf("before-effect SIGKILL: original claim, committed intent and %d original resources retained; no disposal or capacity release", p.ExpectedOwned)
				return
			}
			if ctx.Err() != nil {
				t.Fatal("unknown creation did not quarantine")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	for _, start := range p.Starts {
		stepUntil(start.Spec.ExecutionId, "running")
	}
	if p.CrashController {
		marker := filepath.Join(p.Keys, "qualification-controller-crash")
		f, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_, err = f.WriteString("durable-running-journal\n")
			if err == nil {
				err = f.Sync()
			}
			f.Close()
			dir, e := os.Open(p.Keys)
			if err == nil {
				err = e
			}
			if e == nil {
				if err == nil {
					err = dir.Sync()
				}
				dir.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			t.Fatal("controller SIGKILL returned")
		} else if !os.IsExist(err) {
			t.Fatal(err)
		}
		t.Log("controller SIGKILL recovered original journal and platform watermarks")
	}
	ids, err := c.Runtime.Inventory(ctx)
	if err != nil || len(ids) != len(p.Starts) {
		t.Fatal("parallel inventory lost ownership", ids, err)
	}
	seen := map[string]bool{}
	for _, start := range p.Starts {
		e := current(start.Spec.ExecutionId)
		plan, err := c.plan(e)
		if err != nil {
			t.Fatal(err)
		}
		object, err := c.Runtime.Inspect(ctx, plan.Name, plan)
		if err != nil || seen[object.ID] {
			t.Fatal("parallel resource collision", err)
		}
		seen[object.ID] = true
		if len(p.Starts) > 1 && object.State != "running" {
			t.Fatal("parallel running interval not observed")
		}
	}
	t.Logf("simultaneous jobs under one broker: %d distinct running resources", len(seen))
	for _, start := range p.Starts {
		e := current(start.Spec.ExecutionId)
		plan, err := c.plan(e)
		if err != nil {
			t.Fatal(err)
		}
		if p.ControlledWorkload {
			if _, err = r.post(ctx, "/fixture/finish", phaseDJSON(map[string]string{"executionId": start.Spec.ExecutionId})); err != nil {
				t.Fatal(err)
			}
		}
		for p.KataProfileID == "" {
			object, err := c.Runtime.Inspect(ctx, plan.Name, plan)
			if err != nil {
				t.Fatal(err)
			}
			if object.State == "exited" {
				if object.ExitCode != 0 {
					t.Fatal("workload exit", object.ExitCode)
				}
				break
			}
			if ctx.Err() != nil {
				t.Fatal(ctx.Err())
			}
			time.Sleep(100 * time.Millisecond)
		}
		cleanup := storetest.Encode(t, "HostCommand", map[string]any{"kind": "cleanup", "commandId": "phase-d-cleanup-" + e.Identity.ExecutionID, "executionId": e.Identity.ExecutionID, "generation": e.Identity.Generation})
		if _, err = c.Store.AcceptCommand(ctx, p.Scope, cleanup); err != nil {
			t.Fatal(err)
		}
		if _, err = r.post(ctx, "/fixture/cleanup", phaseDJSON(map[string]string{"executionId": e.Identity.ExecutionID})); err != nil {
			t.Fatal(err)
		}
		stepUntil(e.Identity.ExecutionID, "cleaned")
		if err = c.flushExecutionEvents(ctx, e.Identity.ExecutionID, e.Identity.Generation); err != nil {
			t.Fatal(err)
		}
	}
	if p.KataProfileID != "" {
		e := current(p.Starts[0].Spec.ExecutionId)
		plan, err := c.plan(e)
		if err != nil {
			t.Fatal(err)
		}
		var ref protocol.RuntimeRef
		if json.Unmarshal(e.RuntimeRef, &ref) != nil {
			t.Fatal("native reference")
		}
		proof, err := c.kataPhysicalEvidence(ctx, ref.ResourceId, plan)
		if err != nil || proof.Prepared || proof.Block == nil || proof.Block.Phase != "released" || proof.Absence == nil || !proof.Absence.VMAbsent || !proof.Absence.CgroupRemoved {
			t.Fatal("Kata physical disposal witness", err)
		}
		t.Log("real Kata VM/shim observed; original disk, cgroup and sandbox disposed; native final ACK separate")
	}
	if ids, err = c.Runtime.Inventory(ctx); err != nil || len(ids) != 0 {
		t.Fatal("owned inventory remains", ids, err)
	}
}

func phaseD2SnapshotHeld(t *testing.T, state, ledger string, p phaseDPublic, config broker.Config) {
	t.Helper()
	hashes := map[string]string{}
	for _, root := range []string{ledger, p.State} {
		if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("unexpected evidence symlink")
			}
			if filepath.Base(path) == "instance.lock" {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			hashes[path] = hex.EncodeToString(sum[:])
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	kataHashes := map[string]string{}
	if p.KataProfileID != "" {
		var m katalinux.Manifest
		if json.Unmarshal(p.KataManifest, &m) != nil || m.Storage.Block == nil {
			t.Fatal("held Kata manifest")
		}
		files := []string{filepath.Join(m.Storage.Block.Pool.Root, ".runnerd.owner.json"), filepath.Join(p.KataEvidenceDirectory, "block-slots.json")}
		resources, _ := filepath.Glob(filepath.Join(ledger, "resources", "*.json"))
		for _, file := range resources {
			raw, e := os.ReadFile(file)
			if e != nil {
				t.Fatal(e)
			}
			var record struct{ Name string }
			if json.Unmarshal(raw, &record) != nil {
				t.Fatal("held resource")
			}
			files = append(files, filepath.Join(m.Storage.Block.Pool.Root, record.Name+".raw"), filepath.Join(p.KataEvidenceDirectory, record.Name+".cgroup.json"), filepath.Join(p.KataEvidenceDirectory, record.Name+".json"))
		}
		for _, file := range files {
			f, e := os.Open(file)
			if e != nil {
				t.Fatal(e)
			}
			h := sha256.New()
			_, e = io.Copy(h, f)
			f.Close()
			if e != nil {
				t.Fatal(e)
			}
			kataHashes[file] = hex.EncodeToString(h.Sum(nil))
		}
	}
	machine, e := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if e != nil {
		t.Fatal(e)
	}
	phaseDWrite(t, filepath.Join(state, "held-reboot-evidence.json"), phaseDJSON(map[string]any{"purpose": "runnerd-d2-held-reboot", "boot": strings.TrimSpace(string(boot)), "machineUuid": strings.TrimSpace(string(machine)), "scope": p.Scope, "starts": p.Starts, "ledger": ledger, "journal": p.State, "brokerConfig": config, "publicFixture": p, "hashes": hashes, "kataArtifacts": kataHashes, "productionAdmission": false}), 0600, 0)
	t.Log("held reboot evidence", filepath.Join(state, "held-reboot-evidence.json"))
}

// Trusted fixture completion signal, outside the broker IPC protocol. The
// workload consumes it before exit; unknown files still block broker disposal.
func phaseD2FinishSignals(t *testing.T, fixtures []*phaseDAuthority, root string, scope agent.StoreScope, repository, network string, uid int) {
	t.Helper()
	settings := standardlinux.Settings{ImageRepository: repository, NetworkID: network, BootstrapRoot: root, RunnerUID: uid, PidsLimit: 128}
	for _, fixture := range fixtures {
		p, err := settings.Plan(scope, fixture.start.Spec)
		if err != nil {
			t.Fatal(err)
		}
		fixture.mu.Lock()
		fixture.finish = func() error {
			parent, err := os.OpenRoot(root)
			if err != nil {
				return err
			}
			defer parent.Close()
			dir, err := parent.OpenRoot(p.Name)
			if err != nil {
				return err
			}
			defer dir.Close()
			file, err := dir.OpenFile("fixture-finish", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			_, err = file.WriteString("finish\n")
			if err == nil {
				err = file.Chown(uid, uid)
			}
			if err == nil {
				err = file.Sync()
			}
			file.Close()
			return err
		}
		fixture.mu.Unlock()
	}
}
