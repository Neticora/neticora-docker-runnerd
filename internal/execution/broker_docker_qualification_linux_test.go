//go:build linux && runnerd_broker_qualification

package execution

// Disposable real-Docker engineering smoke. Provider admission and the platform
// database are protocol fixtures; this test cannot qualify production admission.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	"github.com/Neticora/neticora-docker-runnerd/journal"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

type phaseDPublic struct {
	KataEvidenceDirectory, KataJournalDirectory                                             string
	KataManifest                                                                            json.RawMessage
	KataProfileID                                                                           string
	Pool                                                                                    string
	Scope                                                                                   agent.StoreScope
	Start                                                                                   protocol.StartCommand
	Starts                                                                                  []protocol.StartCommand
	BootstrapExpires                                                                        string
	CrashController                                                                         bool
	ControlledWorkload                                                                      bool
	HoldRunning                                                                             bool
	ExpectQuarantine                                                                        bool
	ExpectedOwned                                                                           int
	Policy                                                                                  json.RawMessage
	Socket, Endpoint, URL, CA, Source, Trust, Keys, State, Repository, Network, Provisioned string
}

func phaseDJSON(v any) []byte { raw, _ := json.Marshal(v); return raw }
func phaseDCanonical(v any) []byte {
	raw, err := protocol.CanonicalizeJSON(phaseDJSON(v))
	if err != nil {
		panic(err)
	}
	return raw
}
func phaseDHash(v any) string {
	sum := sha256.Sum256(phaseDCanonical(v))
	return hex.EncodeToString(sum[:])
}
func phaseDSign(domain string, v any, key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), phaseDCanonical(v)...)))
}
func phaseDWrite(t *testing.T, path string, v []byte, mode os.FileMode, uid int) {
	t.Helper()
	if err := os.WriteFile(path, v, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	if uid != 0 {
		if err := os.Chown(path, uid, uid); err != nil {
			t.Fatal(err)
		}
	}
}
func phaseDDir(t *testing.T, path string, mode os.FileMode, uid int) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
	if uid != 0 {
		if err := os.Chown(path, uid, uid); err != nil {
			t.Fatal(err)
		}
	}
}

// TestPhaseDControllerRealDocker owns only its fresh installation, directories,
// network and fixture image. Existing enrolled services/journals are untouched.
func TestPhaseDControllerRealDocker(t *testing.T) {
	if child := os.Getenv("RUNNERD_PHASE_D_CHILD"); child != "" {
		phaseDControllerChild(t, child)
		return
	}
	endpoint, image, network := os.Getenv("RUNNERD_PHASE_D_ENDPOINT"), os.Getenv("RUNNERD_PHASE_D_IMAGE"), os.Getenv("RUNNERD_PHASE_D_NETWORK")
	if endpoint == "" {
		t.Skip("explicit disposable Docker fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("qualification parent must be root")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal("disposable lab marker required")
	}
	parts := strings.Split(image, "@")
	if len(parts) != 2 || !strings.HasPrefix(parts[1], "sha256:") || len(network) != 64 {
		t.Fatal("immutable image and existing bridge required")
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	const uid = 10002
	base, err := os.MkdirTemp("/run", "neticora-phase-d-")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	state, err := os.MkdirTemp("/var/lib", "neticora-phase-d-")
	if err != nil {
		t.Fatal(err)
	}
	private, source, clientTrust, clientKeys, clientState := filepath.Join(base, "private"), filepath.Join(base, "source"), filepath.Join(base, "client-trust"), filepath.Join(state, "keys"), filepath.Join(state, "journal")
	phaseDDir(t, private, 0700, 0)
	phaseDDir(t, source, 0700, uid)
	phaseDDir(t, clientTrust, 0700, uid)
	phaseDDir(t, clientKeys, 0700, uid)
	phaseDDir(t, clientState, 0700, uid)
	// Only the new client directories need traversal; broker ledger remains0700.
	if err = os.Chmod(state, 0755); err != nil {
		t.Fatal(err)
	}
	brokerState := filepath.Join(state, "broker")
	phaseDDir(t, brokerState, 0700, 0)
	issuerPublic, issuer, _ := ed25519.GenerateKey(rand.Reader)
	trace := filepath.Join(state, "fixture-private")
	phaseDDir(t, trace, 0700, 0)
	issuerTrace, _ := x509.MarshalPKCS8PrivateKey(issuer)
	phaseDWrite(t, filepath.Join(trace, "issuer.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: issuerTrace}), 0600, 0)
	disposalPublic, disposal, _ := ed25519.GenerateKey(rand.Reader)
	disposalDER, _ := x509.MarshalPKCS8PrivateKey(disposal)
	phaseDWrite(t, filepath.Join(trace, "disposal.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: disposalDER}), 0600, 0)
	disposalPath := filepath.Join(private, "disposal.pem")
	phaseDWrite(t, disposalPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: disposalDER}), 0600, 0)
	engine, err := dockerengine.Open(endpoint, "phase-d-observer", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	identity, err := engine.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	scope := storetest.Scope
	scope.InstallationID = "phase-d-" + filepath.Base(base)
	scope.EndpointIdentity = identity
	if os.Getenv("RUNNERD_PHASE_E_SEED") != "" {
		scope.InstallationID = "runnerd09-lab-e-" + strings.TrimPrefix(filepath.Base(base), "neticora-phase-d-")
		scope.HostID = scope.InstallationID
		scope.TenantID = scope.InstallationID
	}
	command := storetest.Object(t, storetest.Start(t, "phase-d"))
	spec := command["spec"].(map[string]any)
	spec["templateVersion"] = standardlinux.TemplateVersion
	spec["imageDigest"] = parts[1]
	spec["authorizationExpiresAt"] = now.Add(20 * time.Minute).Format(wireTime)
	kataManifest, kataID := phaseEKataSpec(t, spec, identity)
	if kataID != "" {
		spec["poolId"] = scope.InstallationID
	}

	var start protocol.StartCommand
	raw := storetest.Encode(t, "HostCommand", command)
	if json.Unmarshal(raw, &start) != nil {
		t.Fatal("start fixture")
	}
	starts := []protocol.StartCommand{start}
	jobCount := 1
	if value := os.Getenv("RUNNERD_D2_JOBS"); value != "" {
		jobCount, err = strconv.Atoi(value)
		if err != nil || jobCount < 1 || jobCount > 4 {
			t.Fatal("qualification job count must be 1..4")
		}
	}
	for i := 1; i < jobCount; i++ {
		next := storetest.Object(t, raw)
		next["commandId"] = fmt.Sprintf("phase-d-%d", i)
		s := next["spec"].(map[string]any)
		s["executionId"] = fmt.Sprintf("phase-d-job-%d", i)
		s["attemptId"] = fmt.Sprintf("phase-d-attempt-%d", i)
		var cmd protocol.StartCommand
		_ = json.Unmarshal(storetest.Encode(t, "HostCommand", next), &cmd)
		starts = append(starts, cmd)
	}
	fixtures, err := os.ReadFile("../../api/fixtures/validation.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID    string         `json:"id"`
		Value map[string]any `json:"value"`
	}
	_ = json.Unmarshal(fixtures, &cases)
	var policy map[string]any
	for _, v := range cases {
		if v.ID == "customer-managed-policy-1.1" {
			policy = v.Value
		}
	}
	if policy == nil {
		t.Fatal("policy fixture absent")
	}
	policy["restrictions"].(map[string]any)["runnerUid"] = uid
	if kataID != "" {
		policy["allowedTenantIds"] = []string{scope.TenantID}
		policy["allowedPoolIds"] = []string{scope.InstallationID}
		policy["allowedProfiles"] = []string{kataID}
		resources := start.Spec.Resources
		policy["limits"] = map[string]any{"cpuMillis": resources.CpuMillis, "memoryBytes": resources.MemoryBytes, "storageBytes": resources.StorageBytes, "slots": "1"}
	}
	if jobCount > 1 {
		limits := policy["limits"].(map[string]any)
		resources := start.Spec.Resources
		for field, value := range map[string]string{"cpuMillis": resources.CpuMillis, "memoryBytes": resources.MemoryBytes, "storageBytes": resources.StorageBytes, "slots": resources.Slots} {
			amount, _ := strconv.ParseUint(value, 10, 64)
			limits[field] = strconv.FormatUint(amount*uint64(jobCount), 10)
		}
		policy["maxConcurrentExecutions"] = strconv.Itoa(jobCount)
	}
	images := policy["images"].(map[string]any)
	images["allowedDigests"] = []string{parts[1]}
	images["trustExpiresAt"] = now.Add(time.Hour).Format(wireTime)
	imageKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	imageDER, _ := x509.MarshalPKIXPublicKey(&imageKey.PublicKey)
	rootRaw := phaseDJSON(map[string]any{"version": "neticora-image-key-v1", "rootId": images["trustRootId"], "rootVersion": images["trustRootVersion"], "issuer": images["trustedIssuer"], "subject": images["trustedSubject"], "validUntil": now.Add(time.Hour).Format(wireTime), "publicKeyPem": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: imageDER}))})
	rootHash := sha256.Sum256(rootRaw)
	images["trustRootSha256"] = hex.EncodeToString(rootHash[:])
	payload := phaseDJSON(map[string]any{"critical": map[string]any{"type": "cosign container image signature", "identity": map[string]any{"docker-reference": parts[0]}, "image": map[string]any{"docker-manifest-digest": parts[1]}}})
	payloadHash := sha256.Sum256(payload)
	signature, _ := ecdsa.SignASN1(rand.Reader, imageKey, payloadHash[:])
	bundle := phaseDJSON([]any{map[string]any{"payload": base64.StdEncoding.EncodeToString(payload), "base64Signature": base64.StdEncoding.EncodeToString(signature)}})
	rootName := fmt.Sprint(images["trustRootId"]) + "-" + fmt.Sprint(images["trustRootVersion"]) + ".json"
	for _, row := range []struct {
		dir string
		uid int
	}{{private, 0}, {clientTrust, uid}} {
		phaseDWrite(t, filepath.Join(row.dir, rootName), rootRaw, 0600, row.uid)
		phaseDWrite(t, filepath.Join(row.dir, parts[1][7:]+".sigstore.json"), bundle, 0600, row.uid)
	}
	policyRaw := phaseDJSON(policy)
	policyPath := filepath.Join(private, "policy.json")
	phaseDWrite(t, policyPath, policyRaw, 0600, 0)
	marker := filepath.Join(private, "qualification.json")
	phaseDWrite(t, marker, phaseDJSON(map[string]any{"purpose": "runnerd-phase-d-disposable", "installationId": scope.InstallationID, "hostId": scope.HostID, "endpoint": endpoint, "expiresAt": now.Add(30 * time.Minute).Format(wireTime), "productionAdmission": false}), 0600, 0)
	config := broker.Config{Socket: filepath.Join(base, "broker.sock"), StateDirectory: brokerState, ControllerUID: uid, ControllerGID: uid, Audience: "phase-d-disposable", AuthorityPublicKey: base64.StdEncoding.EncodeToString(issuerPublic), ExecutionGrantPublicKey: base64.StdEncoding.EncodeToString(issuerPublic), Scope: broker.Binding{InstallationID: scope.InstallationID, TenantID: scope.TenantID, HostID: scope.HostID, SessionEpoch: scope.SessionEpoch, EndpointIdentity: scope.EndpointIdentity}, Runtime: &broker.RuntimeConfig{Endpoint: endpoint, PolicyFile: policyPath, ImageRepository: parts[0], NetworkID: network, BootstrapRoot: private, ControllerBootstrapRoot: source, TrustRoots: private, ImageBundles: private, TrustProvisionedAt: now.Add(-time.Minute).Format(wireTime), PidsLimit: 128, Organization: "Neticora", Repository: "Neticora/project", Pool: "pool-a", DisposalKeyFile: disposalPath, QualificationMarker: marker}}
	if kataID != "" {
		config.Runtime.Pool = scope.InstallationID
	}
	// Snapshot directory must be separate from policy/signing material.
	config.Runtime.BootstrapRoot = filepath.Join(private, "handoffs")
	phaseDDir(t, config.Runtime.BootstrapRoot, 0700, 0)
	if action := os.Getenv("RUNNERD_D2_CRASH_OPERATION"); action != "" {
		if os.Getenv("RUNNERD_D2_SYSTEMD") != "1" {
			t.Fatal("broker crash injection requires a separate installed qualification service")
		}
		config.Runtime.QualificationFaultFile = filepath.Join(private, "fault.json")
		point := os.Getenv("RUNNERD_D2_CRASH_POINT")
		if point == "" {
			point = "after-effect"
		}
		phaseDWrite(t, config.Runtime.QualificationFaultFile, phaseDJSON(map[string]string{"operation": action, "point": point, "executionId": start.Spec.ExecutionId}), 0600, 0)
	}
	configPath := filepath.Join(private, "broker.json")
	phaseDWrite(t, configPath, phaseDJSON(config), 0600, 0)
	fixture := newPhaseDAuthority(start, config.Scope, issuer, disposalPublic)
	allFixtures := []*phaseDAuthority{fixture}
	for _, next := range starts[1:] {
		allFixtures = append(allFixtures, newPhaseDAuthority(next, config.Scope, issuer, disposalPublic))
	}
	if bridge := os.Getenv("RUNNERD_PHASE_D_PLATFORM_BRIDGE"); bridge != "" {
		if jobCount != 1 {
			t.Fatal("platform fixture bridge currently requires one job")
		}
		// This optional bridge executes the real TypeScript issuer/commit/disposal
		// service with explicit database/provider fixtures, through an SSH tunnel.
		fixture.bridgeURL = bridge
		tokenFile := os.Getenv("RUNNERD_PHASE_D_PLATFORM_TOKEN_FILE")
		token, readErr := os.ReadFile(tokenFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		fixture.bridgeToken = strings.TrimSpace(string(token))
		issuerDER, _ := x509.MarshalPKCS8PrivateKey(issuer)
		disposalDER, _ := x509.MarshalPKIXPublicKey(disposalPublic)
		_, setupErr := fixture.bridge("/setup", phaseDJSON(map[string]any{"scope": config.Scope, "start": start, "issuer": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: issuerDER})), "disposalPublic": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: disposalDER}))}))
		if setupErr != nil {
			t.Fatal("actual platform fixture setup", setupErr)
		}
		t.Log("actual TypeScript HostDispatchService issuer/commit/disposal; in-memory database and provider fixtures")
	}
	server := httptest.NewTLSServer(phaseD2AuthorityMux(allFixtures))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	public := phaseDPublic{Scope: scope, Start: start, Starts: starts, Policy: policyRaw, Socket: config.Socket, Endpoint: endpoint, URL: server.URL, CA: string(ca), Source: source, Trust: clientTrust, Keys: clientKeys, State: clientState, Repository: parts[0], Network: network, Provisioned: config.Runtime.TrustProvisionedAt}
	public.KataManifest = kataManifest
	public.KataProfileID = kataID
	public.Pool = config.Runtime.Pool
	if kataID != "" {
		phaseEKataBroker(t, &config, kataManifest, policyRaw, server.URL)
		public.KataEvidenceDirectory = config.Runtime.Kata.EvidenceDirectory
		public.KataJournalDirectory = config.Runtime.Kata.JournalDirectory
		phaseDWrite(t, configPath, phaseDJSON(config), 0600, 0)
	}
	public.BootstrapExpires = now.Add(15 * time.Minute).Format(wireTime)
	public.CrashController = os.Getenv("RUNNERD_D2_CONTROLLER_CRASH") == "1"
	public.ControlledWorkload = os.Getenv("RUNNERD_D2_CONTROLLED_WORKLOAD") == "1"
	public.HoldRunning = os.Getenv("RUNNERD_E3_HOLD_RUNNING") == "1"
	public.ExpectQuarantine = os.Getenv("RUNNERD_D2_EXPECT_QUARANTINE") == "1"
	if os.Getenv("RUNNERD_D2_EXPECT_OWNED") == "1" {
		public.ExpectedOwned = 1
	}
	expectedCrash := "CreateExecution"
	if public.ExpectedOwned == 1 {
		expectedCrash = "StartExecution"
	}
	if public.ExpectQuarantine && (jobCount != 1 || os.Getenv("RUNNERD_D2_CRASH_OPERATION") != expectedCrash || os.Getenv("RUNNERD_D2_CRASH_POINT") != "before-effect") {
		t.Fatal("held qualification requires one exact before-effect crash")
	}
	if public.ControlledWorkload {
		phaseD2FinishSignals(t, allFixtures, config.Runtime.BootstrapRoot, scope, parts[0], network, uid)
	}
	publicPath := filepath.Join(base, "public.json")
	phaseDWrite(t, publicPath, phaseDJSON(public), 0644, 0)
	// Positive denial controls: listening privileged sockets, rather than only
	// absent paths. Existing runtime sockets are observed without replacement.
	for _, socket := range []string{"/run/docker.sock", "/run/containerd/containerd.sock", filepath.Join(base, "alternate.sock")} {
		if _, err = os.Lstat(socket); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err = os.MkdirAll(filepath.Dir(socket), 0755); err != nil {
			t.Fatal(err)
		}
		listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
		if e != nil {
			t.Fatal(e)
		}
		if e = os.Chmod(socket, 0600); e != nil {
			listener.Close()
			t.Fatal(e)
		}
		t.Cleanup(func() { listener.Close() })
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	var installed *phaseD2Services
	if os.Getenv("RUNNERD_D2_SYSTEMD") == "1" {
		installed = phaseD2InstallBroker(t, base, state, configPath)
		defer installed.close(t)
	} else {
		go func() { done <- broker.Serve(ctx, configPath) }()
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err = os.Stat(config.Socket); err == nil {
			break
		}
		select {
		case err = <-done:
			t.Fatal("broker startup", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("broker socket timeout")
		}
		time.Sleep(30 * time.Millisecond)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(self, "-test.run=^TestPhaseDControllerRealDocker$", "-test.v")
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "RUNNERD_PHASE_D_PLATFORM_") {
			child.Env = append(child.Env, value)
		}
	}
	child.Env = append(child.Env, "RUNNERD_PHASE_D_CHILD="+publicPath, "TMPDIR=/var/tmp")
	child.Env = append(child.Env, "DOCKER_HOST=unix://"+filepath.Join(base, "alternate.sock"))
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}}
	finishHeldBlock := phaseE2HoldBlock(t, public, state, brokerState)
	var output []byte
	if installed != nil {
		output, err = installed.controller(t, self, publicPath, public, false)
	} else {
		var collected bytes.Buffer
		child.Stdout = io.MultiWriter(os.Stdout, &collected)
		child.Stderr = io.MultiWriter(os.Stdout, &collected)
		err = child.Run()
		output = collected.Bytes()
	}
	t.Log(string(output))
	if err != nil {
		t.Fatalf("controller child: %v; retained ownership: %s", err, state)
	}
	if holdErr := finishHeldBlock(); holdErr != nil {
		t.Fatal("uncertain Kata disposal qualification", holdErr)
	}
	// Deliberately inherited live Docker FD must be refused before any runtime
	// or platform operation, even though pathname permissions deny new connects.
	connection, err := net.Dial("unix", strings.TrimPrefix(endpoint, "unix://"))
	if err != nil {
		t.Fatal(err)
	}
	fd, err := connection.(*net.UnixConn).File()
	connection.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	probe := exec.Command(self, "-test.run=^TestPhaseDControllerRealDocker$", "-test.v")
	probe.Env = append(child.Env, "RUNNERD_PHASE_D_INHERITED=1")
	probe.SysProcAttr = child.SysProcAttr
	probe.ExtraFiles = []*os.File{fd}
	if installed != nil {
		output, err = installed.controller(t, self, publicPath, public, true)
	} else {
		output, err = probe.CombinedOutput()
	}
	t.Log(string(output))
	if err != nil {
		t.Fatal("inherited FD denial failed", err)
	}
	for _, f := range allFixtures {
		f.mu.Lock()
		disposed, counts := f.disposed, len(f.commits)
		f.mu.Unlock()
		if public.ExpectQuarantine || public.HoldRunning {
			if disposed || counts != 2+public.ExpectedOwned {
				t.Fatal("unknown create lost committed obligations", counts)
			}
		} else if !disposed || counts != 5 {
			t.Fatal("exact five commitments/disposal not observed", counts)
		}
	}
	if public.ExpectQuarantine || public.HoldRunning {
		phaseD2SnapshotHeld(t, state, brokerState, public, config)
	} else {
		phaseD2CreatedExactly(t, endpoint, scope.InstallationID, now, allFixtures)
	}
	if config.Runtime.QualificationFaultFile != "" {
		if _, err = os.Stat(config.Runtime.QualificationFaultFile + ".consumed"); err != nil {
			t.Fatal("requested broker SIGKILL never occurred", err)
		}
		output, err := phaseD2Command("systemctl", "show", installed.broker, "-p", "NRestarts", "--value")
		if err != nil || strings.TrimSpace(string(output)) != "1" {
			t.Fatal("broker did not restart exactly once", string(output), err)
		}
		t.Log("broker SIGKILL recovered original operations; exactly one systemd restart")
	}
	cancel()
	if installed == nil {
		err = <-done
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("engineering smoke passed: %d jobs, real Docker through one broker/controller, UID %d; state retained at %s", jobCount, uid, state)
}

type phaseDAuthority struct {
	mu                          sync.Mutex
	start                       protocol.StartCommand
	scope                       broker.Binding
	key                         ed25519.PrivateKey
	disposalKey                 ed25519.PublicKey
	grants                      map[string]broker.SignedExecutionGrant
	commits                     map[string]broker.SignedCommit
	challenge                   broker.SignedDisposalChallenge
	resource                    string
	prepared, cleanup, disposed bool
	ack                         string
	inventory                   string
	finish                      func() error
	finished                    bool
	bridgeURL, bridgeToken      string
}

func (f *phaseDAuthority) bridge(path string, raw []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", f.bridgeURL+path, strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+f.bridgeToken)
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) > 65536 {
		return nil, ErrReconcile
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("platform fixture rejected %s: %s", path, string(body))
	}
	return body, nil
}

func newPhaseDAuthority(start protocol.StartCommand, scope broker.Binding, key ed25519.PrivateKey, disposal ed25519.PublicKey) *phaseDAuthority {
	return &phaseDAuthority{start: start, scope: scope, key: key, disposalKey: disposal, inventory: "1", grants: map[string]broker.SignedExecutionGrant{}, commits: map[string]broker.SignedCommit{}}
}
func (f *phaseDAuthority) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	raw, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	if err != nil || len(raw) > 65536 {
		w.WriteHeader(400)
		return
	}
	send := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	deny := func() { w.WriteHeader(409); send(map[string]string{"error": "fixture authority rejected"}) }
	now := time.Now().UTC().Truncate(time.Millisecond)
	if r.URL.Path == "/fixture/finish" {
		if !f.finished {
			if f.finish == nil || f.finish() != nil {
				deny()
				return
			}
			f.finished = true
		}
		send(map[string]bool{"ok": true})
		return
	}
	if r.URL.Path == "/fixture/watermark" {
		sequence := f.ack
		if sequence == "" {
			sequence = "0"
		}
		send(map[string]string{"sequence": sequence, "inventoryGeneration": f.inventory})
		return
	}
	if r.URL.Path == "/fixture/inventory" {
		var input struct {
			InventoryGeneration string `json:"inventoryGeneration"`
		}
		if json.Unmarshal(raw, &input) != nil || input.InventoryGeneration == "" {
			deny()
			return
		}
		f.inventory = input.InventoryGeneration
		send(map[string]bool{"ok": true})
		return
	}
	if f.bridgeURL != "" && strings.Contains(r.URL.Path, "/broker/") {
		path := r.URL.Path[strings.Index(r.URL.Path, "/broker/"):]
		body, err := f.bridge(path, raw)
		if err != nil {
			w.WriteHeader(409)
			send(map[string]string{"error": err.Error()})
			return
		}
		switch path {
		case "/broker/commit":
			var certificate broker.SignedCommit
			if json.Unmarshal(body, &certificate) != nil {
				deny()
				return
			}
			f.commits[certificate.Commit.OperationID] = certificate
		case "/broker/disposal":
			f.disposed = true
		}
		w.Write(body)
		return
	}
	if r.URL.Path == "/fixture/events" {
		var batch protocol.EventBatch
		if protocol.ValidateInboundJSON("EventBatch", raw) != nil || json.Unmarshal(raw, &batch) != nil {
			deny()
			return
		}
		acks := []protocol.EventAck{}
		if f.bridgeURL != "" {
			if _, err = f.bridge("/fixture/events", raw); err != nil {
				deny()
				return
			}
		}
		for _, event := range batch.Events {
			if event.Observation != nil {
				ob := event.Observation
				if ob.State == "prepared" {
					f.prepared = true
					f.resource = ob.RuntimeRef.ResourceId
				}
				if ob.State == "cleaned" && !f.disposed {
					deny()
					return
				}
			}
			acks = append(acks, protocol.EventAck{ExecutionId: event.ExecutionId, Generation: event.Generation, ContiguousSequence: event.Sequence})
			f.ack = event.Sequence
		}
		send(acks)
		return
	}
	if r.URL.Path == "/fixture/cleanup" {
		if f.bridgeURL != "" {
			if _, err = f.bridge("/fixture/cleanup", raw); err != nil {
				deny()
				return
			}
		}
		f.cleanup = true
		send(map[string]bool{"ok": true})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/broker/grant") {
		var q broker.ExecutionGrantRequest
		if json.Unmarshal(raw, &q) != nil || q.Validate() != nil || q.ExecutionID != f.start.Spec.ExecutionId || q.Generation != f.start.Generation {
			deny()
			return
		}
		states := map[string]string{"PrepareImage": "ALLOCATED", "CreateExecution": "ALLOCATED", "StartExecution": "PREPARED", "StopExecution": "STOPPING", "RemoveExecution": "STOPPED"}
		if states[q.Operation] == "" || (q.Operation == "StartExecution" && !f.prepared) || ((q.Operation == "StopExecution" || q.Operation == "RemoveExecution") && !f.cleanup) || (q.ResourceID != "" && q.ResourceID != f.resource) {
			deny()
			return
		}
		binding := f.scope
		binding.ExecutionID = q.ExecutionID
		binding.Generation = q.Generation
		binding.SpecHash = f.start.Spec.SpecHash
		binding.AttemptID = f.start.Spec.AttemptId
		g := broker.ExecutionGrant{Version: broker.ExecutionGrantVersion, Audience: "neticora-broker:" + binding.InstallationID, Operation: q.Operation, OperationID: q.OperationID, ExpectedRevision: q.ExpectedRevision, ExpectedState: states[q.Operation], ResourceID: q.ResourceID, Challenge: q.Challenge, Binding: binding, Spec: f.start.Spec, NotBefore: now.Format(wireTime), ExpiresAt: now.Add(15 * time.Second).Format(wireTime)}
		s := broker.SignedExecutionGrant{Grant: g, Signature: phaseDSign("neticora-runnerd-broker-execution-grant-v1\n", g, f.key)}
		f.grants[q.OperationID] = s
		send(s)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/broker/commit") {
		var q broker.CommitRequest
		if json.Unmarshal(raw, &q) != nil {
			deny()
			return
		}
		g, ok := f.grants[q.Request.OperationID]
		if !ok || phaseDHash(g) != phaseDHash(q.Grant) {
			deny()
			return
		}
		c := broker.Commit{Version: "runnerd-broker-commit-v1", Audience: g.Grant.Audience, OperationID: g.Grant.OperationID, GrantHash: phaseDHash(g), Challenge: g.Grant.Challenge, Binding: g.Grant.Binding, State: "COMMITTED", NotBefore: now.Format(wireTime), ExpiresAt: g.Grant.ExpiresAt}
		s := broker.SignedCommit{Commit: c, Signature: phaseDSign("neticora-runnerd-broker-commit-v1\n", c, f.key)}
		f.commits[c.OperationID] = s
		send(s)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/disposal/challenge") {
		var q broker.Lookup
		if json.Unmarshal(raw, &q) != nil || q.ResourceID != f.resource || len(f.commits) != 5 {
			deny()
			return
		}
		ids := []string{}
		var binding broker.Binding
		for id, c := range f.commits {
			ids = append(ids, id)
			binding = c.Commit.Binding
		}
		slices.Sort(ids)
		nonce := make([]byte, 32)
		_, _ = rand.Read(nonce)
		c := broker.DisposalChallenge{Version: broker.DisposalVersion, Binding: binding, ResourceID: f.resource, OperationIDs: ids, Nonce: hex.EncodeToString(nonce), NotBefore: now.Format(wireTime), ExpiresAt: now.Add(time.Minute).Format(wireTime)}
		f.challenge = broker.SignedDisposalChallenge{Challenge: c, Signature: phaseDSign(broker.DisposalChallengeDomain, c, f.key)}
		send(f.challenge)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/broker/disposal") {
		proof, err := broker.DecodeDisposal(raw)
		if err != nil {
			deny()
			return
		}
		sig, e := base64.StdEncoding.Strict().DecodeString(proof.Signature)
		if e != nil || proof.Disposal.ChallengeHash != phaseDHash(f.challenge) || phaseDHash(proof.Challenge) != phaseDHash(f.challenge) || proof.Disposal.State != "REMOVED" || proof.Disposal.ResourceID != f.resource || !ed25519.Verify(f.disposalKey, append([]byte(broker.DisposalDomain), phaseDCanonical(proof.Disposal)...), sig) {
			deny()
			return
		}
		f.disposed = true
		send(map[string]string{"state": "VERIFIED"})
		return
	}
	deny()
}

type phaseDRemote struct {
	*fakeRemote
	client        *http.Client
	url, endpoint string
	ack           string
	starts        []protocol.StartCommand
	acks          map[string]string
	cancelled     map[string]bool
}

func (r *phaseDRemote) Events(ctx context.Context, m protocol.Outbound) ([]protocol.EventAck, error) {
	raw, err := r.post(ctx, "/fixture/events", m.Bytes())
	if err != nil {
		return nil, err
	}
	var acks []protocol.EventAck
	err = json.Unmarshal(raw, &acks)
	if len(acks) > 0 {
		r.ack = acks[len(acks)-1].ContiguousSequence
	}
	for _, ack := range acks {
		if r.acks != nil {
			r.acks[ack.ExecutionId] = ack.ContiguousSequence
		}
	}
	return acks, err
}
func (r *phaseDRemote) Inventory(ctx context.Context, m protocol.Outbound) error {
	if err := r.fakeRemote.Inventory(ctx, m); err != nil {
		return err
	}
	_, err := r.post(ctx, "/fixture/inventory", phaseDJSON(map[string]string{"executionId": r.starts[0].Spec.ExecutionId, "inventoryGeneration": r.inventory}))
	return err
}
func (r *phaseDRemote) post(ctx context.Context, path string, raw []byte) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "POST", r.url+path, strings.NewReader(string(raw)))
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode != 200 {
		return nil, ErrReconcile
	}
	if path == "/fixture/cleanup" && r.cancelled != nil {
		var q struct {
			ExecutionID string `json:"executionId"`
		}
		_ = json.Unmarshal(raw, &q)
		r.cancelled[q.ExecutionID] = true
	}
	return body, err
}
func (r *phaseDRemote) Recovery(ctx context.Context, q []agent.ExecutionCursor) (protocol.RecoveryState, error) {
	state, err := r.fakeRemote.Recovery(ctx, q)
	state.EndpointIdentity = r.endpoint
	if len(r.starts) > 0 {
		state.Entries = nil
		for _, start := range r.starts {
			ack := r.acks[start.Spec.ExecutionId]
			if ack == "" {
				ack = "0"
			}
			state.Entries = append(state.Entries, protocol.RecoveryEntry{ExecutionId: start.Spec.ExecutionId, Generation: start.Generation, CommandId: start.CommandId, SpecHash: start.Spec.SpecHash, ContiguousSequence: ack, Cancelled: r.cancelled[start.Spec.ExecutionId]})
		}
		return state, err
	}
	for i := range state.Entries {
		state.Entries[i].ContiguousSequence = r.ack
	}
	return state, err
}

func phaseDControllerChild(t *testing.T, path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var p phaseDPublic
	if json.Unmarshal(raw, &p) != nil {
		t.Fatal("public fixture")
	}
	err = checkBrokerContainment(p.Endpoint)
	if os.Getenv("RUNNERD_PHASE_D_INHERITED") == "1" {
		if err == nil || !strings.Contains(err.Error(), "inherited socket descriptor") {
			t.Fatal("inherited Docker descriptor accepted", err)
		}
		t.Log("inherited live Docker FD rejected")
		return
	}
	if err != nil {
		t.Fatal("controller retains privilege", err)
	}
	if os.Getenv("RUNNERD_D2_SYSTEMD") == "1" {
		status, _ := os.ReadFile("/proc/self/status")
		if !strings.Contains(string(status), "NoNewPrivs:\t1") {
			t.Fatal("installed service lacks NoNewPrivileges")
		}
	}
	// Root issuer and disposal secrets must be inaccessible to this process.
	if _, err = os.ReadFile(filepath.Join(filepath.Dir(path), "private", "disposal.pem")); !os.IsPermission(err) {
		t.Fatal("broker disposal key readable", err)
	}
	policy, err := standardlinux.ParsePolicy(p.Policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	s, err := journal.OpenRecovery(ctx, p.State, journal.Options{ReservationLimits: policy.Limits()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(p.Starts) == 0 {
		p.Starts = []protocol.StartCommand{p.Start}
	}
	client, err := transport.NewWithRoots(p.URL, 15*time.Second, []byte(p.CA))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	httpClient := &http.Client{Transport: clientHTTPTransport(p.CA)}
	r := &phaseDRemote{fakeRemote: &fakeRemote{t: t, start: p.Start, inventory: "1", expires: p.BootstrapExpires, tenant: p.Scope.TenantID, host: p.Scope.HostID}, url: p.URL, client: httpClient, endpoint: p.Scope.EndpointIdentity, ack: "0", starts: p.Starts, acks: map[string]string{}, cancelled: map[string]bool{}}
	var watermarks []agent.Watermark
	for _, start := range p.Starts {
		if _, lookupErr := s.PeerRecoveryExecution(ctx, start.Spec.ExecutionId, start.Generation); lookupErr == nil {
			body, err := r.post(ctx, "/fixture/watermark", phaseDJSON(map[string]string{"executionId": start.Spec.ExecutionId}))
			if err != nil {
				t.Fatal(err)
			}
			var reply struct {
				Sequence            string `json:"sequence"`
				InventoryGeneration string `json:"inventoryGeneration"`
			}
			if json.Unmarshal(body, &reply) != nil || reply.Sequence == "" {
				t.Fatal("authoritative restart watermark missing")
			}
			r.acks[start.Spec.ExecutionId] = reply.Sequence
			// Installation-wide inventory is stored on the first fixture.
			if start.Spec.ExecutionId == p.Starts[0].Spec.ExecutionId {
				r.inventory = reply.InventoryGeneration
			}
			watermarks = append(watermarks, agent.Watermark{ExecutionID: start.Spec.ExecutionId, Generation: start.Generation, ContiguousSequence: reply.Sequence})
		} else if !errors.Is(lookupErr, agent.ErrNotFound) {
			t.Fatal(lookupErr)
		}
	}
	if len(watermarks) == 0 {
		storetest.Reconcile(t, s, p.Scope, "1")
		for _, start := range p.Starts {
			if _, err = s.AcceptCommand(ctx, p.Scope, phaseDJSON(start)); err != nil {
				t.Fatal(err)
			}
		}
	}
	remote := &HostRemote{Client: client, token: "disposable-fixture", expires: time.Now().Add(time.Hour)}
	lost := map[string]bool{}
	lossFile := filepath.Join(p.Keys, "qualification-lost-replies.json")
	if saved, readErr := os.ReadFile(lossFile); readErr == nil {
		if json.Unmarshal(saved, &lost) != nil {
			t.Fatal("lost-reply witness corrupt")
		}
	} else if !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	saveLoss := func() {
		temporary := lossFile + ".pending"
		f, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write(phaseDJSON(lost))
		if err == nil {
			err = f.Sync()
		}
		_ = f.Close()
		if err == nil {
			err = os.Rename(temporary, lossFile)
		}
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
	}
	remote.brokerCall = func(ctx context.Context, socket string, q broker.Request) (broker.Response, error) {
		response, err := broker.Call(ctx, socket, q)
		if err != nil {
			t.Logf("qualification broker %s: %s", q.Operation, response.Code)
		}
		if q.Operation == "ExecuteOperation" && q.ExecutionRequest != nil {
			action := q.ExecutionRequest.Operation
			key := q.ExecutionRequest.ExecutionID + ":" + action
			if err != nil && (response.Code == "" || response.Code == "reconciliation_required") && (action == "CreateExecution" || action == "StartExecution" || action == "RemoveExecution") {
				// A real ambiguous/partial response already exercises reconciliation.
				// Do not demand a synthetic success-reply loss as a second authority path.
				lost[key] = true
				saveLoss()
				t.Logf("original %s response uncertain (%s); reconcile the same operation", action, response.Code)
			}
			if err != nil {
				return response, err
			}
			if (action == "CreateExecution" || action == "StartExecution" || action == "RemoveExecution") && !lost[key] {
				lost[key] = true
				saveLoss()
				return broker.Response{}, dockerengine.ErrUnavailable
			}
		}
		return response, err
	}
	provisioned, _ := time.Parse(time.RFC3339Nano, p.Provisioned)
	verifier := standardlinux.ImageVerifier{RootDirectory: p.Trust, BundleDirectory: p.Trust, ProvisionedAt: provisioned}
	c := &Controller{Store: s, Remote: r, Scope: p.Scope, Authority: journal.Authority{TenantID: p.Scope.TenantID, HostID: p.Scope.HostID, SessionEpoch: p.Scope.SessionEpoch, EndpointIdentity: p.Scope.EndpointIdentity, KeyID: "key-a"}, Profile: standardlinux.Settings{ImageRepository: p.Repository, NetworkID: p.Network, BootstrapRoot: p.Source, RunnerUID: os.Geteuid(), PidsLimit: 128}, Policy: func() *standardlinux.Policy { return policy }, VerifyImage: verifier.Verify, KeysDirectory: p.Keys, Organization: "Neticora", Repository: "Neticora/project", Pool: p.Pool, Drained: func() bool { return false }, cancelled: map[agent.ExecutionCursor]bool{}}
	c.Runtime = brokerRuntimeFor(c, remote, p.Socket)
	phaseEKataController(t, c, p)
	c.heartbeatGeneration.Store("1")
	if len(watermarks) > 0 {
		// Recover through the original controller inventory/watermark flow,
		// never replay the fixture's initial inventory generation.
		if _, err = c.refresh(ctx); err != nil {
			t.Fatal("controller restart reconciliation", err)
		}
	}
	phaseD2RunJobs(t, ctx, c, p, r)
	if p.ExpectQuarantine {
		return
	}
	if len(lost) != 3*len(p.Starts) {
		t.Fatal("uncertain operation response coverage incomplete", lost)
	}
	if p.KataProfileID == "" {
		t.Log("real workload exit=0; original creation/start journal retained; broker disposal accepted before final cleaned event")
	} else {
		t.Log("broker-backed Kata launch/cancel/dispose; provider workload not qualified")
	}
}

func clientHTTPTransport(ca string) *http.Transport {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(ca))
	return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
}
