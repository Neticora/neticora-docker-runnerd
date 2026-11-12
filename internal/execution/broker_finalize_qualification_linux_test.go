//go:build linux && runnerd_broker_qualification && runnerd_qualification

package execution

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/broker"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
)

// Actual runnerd/broker executables, original journal and real Kata disposal.
// The TLS platform/provider remains an explicit durable protocol fixture, not
// release qualification. Missing original platform history is never regenerated.
func TestPhaseFBrokerNativeFinalizationLab(t *testing.T) {
	input, binary := os.Getenv("RUNNERD_F_HELD_STATE"), os.Getenv("RUNNERD_F_DAEMON_BINARY")
	if input == "" || binary == "" {
		t.Skip("explicit retained Phase F fixture and installed daemon required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root lab coordinator required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(input, "/var/lib/neticora-phase-d-") || filepath.Clean(input) != input {
		t.Fatal("wrong original fixture")
	}
	raw, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		Boot, Ledger, Journal string
		BrokerConfig          broker.Config
		PublicFixture         phaseDPublic
		ProductionAdmission   bool
	}
	if json.Unmarshal(raw, &snapshot) != nil || snapshot.ProductionAdmission || snapshot.BrokerConfig.Runtime == nil || snapshot.BrokerConfig.Runtime.Kata == nil {
		t.Fatal("original Kata fixture absent")
	}
	if strings.TrimSpace(string(mustPhaseFBoot(t))) == snapshot.Boot {
		t.Fatal("real boot boundary required")
	}
	state := filepath.Dir(snapshot.Ledger)
	p := snapshot.PublicFixture
	var history struct {
		Start                       protocol.StartCommand
		Scope                       broker.Binding
		Grants                      map[string]broker.SignedExecutionGrant
		Commits                     map[string]broker.SignedCommit
		Resource, Ack, Inventory    string
		Prepared, Cleanup, Disposed bool
	}
	raw, err = os.ReadFile(filepath.Join(state, "fixture-private", "platform-history.json"))
	if err != nil || json.Unmarshal(raw, &history) != nil || len(history.Commits) != 3 || history.Resource == "" {
		t.Fatal("original durable platform commitments required; no reconstruction", err)
	}
	issuer := phaseFPrivate(t, filepath.Join(state, "fixture-private", "issuer.pem"))
	defer clear(issuer)
	disposal := phaseFPrivate(t, filepath.Join(state, "fixture-private", "disposal.pem"))
	defer clear(disposal)
	for id, commit := range history.Commits {
		grant, ok := history.Grants[id]
		sig, e := base64.StdEncoding.DecodeString(commit.Signature)
		if !ok || e != nil || commit.Commit.GrantHash != phaseDHash(grant) || !ed25519.Verify(issuer.Public().(ed25519.PublicKey), append([]byte("neticora-runnerd-broker-commit-v1\n"), phaseDCanonical(commit.Commit)...), sig) {
			t.Fatal("original commitment invalid")
		}
	}
	f := newPhaseDAuthority(history.Start, history.Scope, issuer, disposal.Public().(ed25519.PublicKey))
	f.grants = history.Grants
	f.commits = history.Commits
	f.resource = history.Resource
	f.ack = history.Ack
	f.inventory = history.Inventory
	f.prepared = history.Prepared
	f.cleanup = true
	// New terminal intent is legitimate fixture authority, not rewritten history.
	cleanup := storetest.Encode(t, "HostCommand", map[string]any{"kind": "cleanup", "commandId": "phase-f-cleanup-" + history.Start.Spec.ExecutionId, "executionId": history.Start.Spec.ExecutionId, "generation": history.Start.Generation})
	credentialPath := filepath.Join(state, "client-credentials.json")
	credentialBefore, err := os.ReadFile(credentialPath)
	if err != nil {
		t.Fatal("original host identity missing", err)
	}
	var credentials Credentials
	if json.Unmarshal(credentialBefore, &credentials) != nil {
		t.Fatal("credential fixture")
	}
	block, _ := pem.Decode([]byte(credentials.PrivateKeyPEM))
	if block == nil {
		t.Fatal("credential key")
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	hostPublic := key.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	token := make([]byte, 32)
	rand.Read(token)
	access := base64.RawURLEncoding.EncodeToString(token)
	bootAuthorities := map[string]broker.SignedBootCertificate{}
	lostAck := false
	save := func() {
		phaseDWrite(t, filepath.Join(state, "fixture-private", "finalization-platform.json"), phaseDJSON(map[string]any{"bootAuthorities": bootAuthorities, "disposed": f.disposed, "ack": f.ack, "inventory": f.inventory, "originalCommitments": f.commits}), 0600, 0)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 65537))
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/runner-hosts")
		send := func(v any) { w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(v) }
		deny := func() { w.WriteHeader(409) }
		if path == "/token" {
			var q struct{ Assertion string }
			json.Unmarshal(raw, &q)
			parts := strings.Split(q.Assertion, ".")
			if len(parts) != 3 {
				deny()
				return
			}
			sig, e := base64.RawURLEncoding.DecodeString(parts[2])
			body, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var claims map[string]any
			json.Unmarshal(body, &claims)
			if e != nil || !ed25519.Verify(hostPublic, []byte(parts[0]+"."+parts[1]), sig) || claims["sub"] != credentials.Identity.HostId || claims["bootId"] != credentials.BootID || claims["sessionEpoch"] != credentials.Identity.SessionEpoch {
				deny()
				return
			}
			send(map[string]any{"accessToken": access, "expiresAt": time.Now().UTC().Add(10 * time.Minute).Format(wireTime)})
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+access {
			w.WriteHeader(401)
			return
		}
		switch path {
		case "/me/commands":
			send([]json.RawMessage{cleanup})
			return
		case "/me/commands/ack":
			w.WriteHeader(204)
			return
		case "/me/recovery":
			ack := f.ack
			if ack == "" {
				ack = "0"
			}
			send(protocol.RecoveryState{Identity: credentials.Identity, EndpointIdentity: credentials.EndpointIdentity, InventoryGeneration: f.inventory, Entries: []protocol.RecoveryEntry{{ExecutionId: f.start.Spec.ExecutionId, Generation: f.start.Generation, CommandId: f.start.CommandId, SpecHash: f.start.Spec.SpecHash, ContiguousSequence: ack, Cancelled: true}}})
			return
		case "/me/inventory":
			var q protocol.InventorySnapshot
			if json.Unmarshal(raw, &q) != nil || !q.Complete || len(q.Resources) != 0 || q.EndpointIdentity != credentials.EndpointIdentity {
				deny()
				return
			}
			f.inventory = q.InventoryGeneration
			save()
			w.WriteHeader(204)
			return
		case "/me/events":
			clone := r.Clone(r.Context())
			clone.URL.Path = "/fixture/events"
			clone.Body = io.NopCloser(bytes.NewReader(raw))
			reply := httptest.NewRecorder()
			f.ServeHTTP(reply, clone)
			save()
			var batch protocol.EventBatch
			json.Unmarshal(raw, &batch)
			final := false
			for _, event := range batch.Events {
				if event.Observation != nil && event.Observation.State == "cleaned" {
					final = true
				}
			}
			if final && !lostAck && reply.Code == 200 {
				lostAck = true
				conn, _, e := w.(http.Hijacker).Hijack()
				if e == nil {
					conn.Close()
				}
				return
			}
			w.WriteHeader(reply.Code)
			w.Write(reply.Body.Bytes())
			return
		case "/me/broker/boot-recovery":
			var challenge broker.SignedBootChallenge
			if json.Unmarshal(raw, &challenge) != nil {
				deny()
				return
			}
			sig, e := base64.StdEncoding.DecodeString(challenge.Signature)
			ch := challenge.Challenge
			ids := []string{}
			for id := range f.commits {
				ids = append(ids, id)
			}
			slices.Sort(ids)
			if e != nil || !ed25519.Verify(f.disposalKey, append([]byte(broker.BootChallengeDomain), phaseDCanonical(ch)...), sig) || ch.ResourceID != f.resource || !slices.Equal(ch.OperationIDs, ids) || ch.Binding.ExecutionID != f.start.Spec.ExecutionId || ch.Binding.SpecHash != f.start.Spec.SpecHash {
				deny()
				return
			}
			id := phaseDHash(challenge)
			authority, ok := bootAuthorities[id]
			if !ok {
				c := broker.BootCertificate{Version: broker.BootRecoveryVersion, Operation: "RecoverBootCleanup", ID: id, Challenge: challenge, NotBefore: time.Now().UTC().Format(wireTime), ExpiresAt: ch.ExpiresAt}
				authority = broker.SignedBootCertificate{Certificate: c, Signature: phaseDSign(broker.BootRecoveryDomain, c, issuer)}
				bootAuthorities[id] = authority
			}
			save()
			send(authority)
			return
		case "/me/broker/disposal/challenge":
			var q broker.Lookup
			if json.Unmarshal(raw, &q) != nil || q.ResourceID != f.resource || q.RecoveryID == "" {
				deny()
				return
			}
			authority, ok := bootAuthorities[q.RecoveryID]
			if !ok {
				deny()
				return
			}
			now := time.Now().UTC()
			nonce := make([]byte, 32)
			rand.Read(nonce)
			c := broker.DisposalChallenge{Version: broker.DisposalVersion, Binding: authority.Certificate.Challenge.Challenge.Binding, ResourceID: f.resource, OperationIDs: authority.Certificate.Challenge.Challenge.OperationIDs, Nonce: hex.EncodeToString(nonce), NotBefore: now.Format(wireTime), ExpiresAt: now.Add(time.Minute).Format(wireTime), RecoveryID: q.RecoveryID}
			f.challenge = broker.SignedDisposalChallenge{Challenge: c, Signature: phaseDSign(broker.DisposalChallengeDomain, c, issuer)}
			send(f.challenge)
			return
		case "/me/broker/disposal":
			proof, e := broker.DecodeDisposal(raw)
			if e != nil {
				deny()
				return
			}
			sig, e := base64.StdEncoding.DecodeString(proof.Signature)
			if e != nil || proof.Disposal.ChallengeHash != phaseDHash(f.challenge) || proof.Disposal.State != "RECOVERY_DISPOSED" || proof.Disposal.ResourceID != f.resource || proof.Disposal.RecoveryID != f.challenge.Challenge.RecoveryID || !ed25519.Verify(f.disposalKey, append([]byte(broker.DisposalDomain), phaseDCanonical(proof.Disposal)...), sig) {
				deny()
				return
			}
			phaseDWrite(t, filepath.Join(state, "fixture-private", "finalization-disposal-proof.json"), raw, 0600, 0)
			f.disposed = true
			save()
			send(map[string]string{"state": "VERIFIED"})
			return
		}
		deny()
	})
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	base, err := os.MkdirTemp("/run", "neticora-phase-f-")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(base, 0755)
	clientDir := filepath.Join(base, "client")
	phaseDDir(t, clientDir, 0700, 10002)
	ca := filepath.Join(clientDir, "ca.pem")
	phaseDWrite(t, ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600, 10002)
	policy := filepath.Join(clientDir, "policy.json")
	phaseDWrite(t, policy, p.Policy, 0600, 10002)
	c := snapshot.BrokerConfig
	c.Socket = filepath.Join(base, "broker.sock")
	x := c.Runtime
	x.BootRecoveryOnly = true
	x.QualificationFaultFile = ""
	x.PolicyFile = filepath.Join(base, "policy.json")
	phaseDWrite(t, x.PolicyFile, p.Policy, 0600, 0)
	x.DisposalKeyFile = filepath.Join(state, "fixture-private", "disposal.pem")
	for _, path := range []string{x.BootstrapRoot, x.ControllerBootstrapRoot} {
		if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err = os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
	}
	os.Chown(x.ControllerBootstrapRoot, 10002, 10002)
	x.QualificationMarker = filepath.Join(base, "marker.json")
	phaseDWrite(t, x.QualificationMarker, phaseDJSON(map[string]any{"purpose": "runnerd-phase-d-disposable", "installationId": c.Scope.InstallationID, "hostId": c.Scope.HostID, "endpoint": x.Endpoint, "expiresAt": time.Now().UTC().Add(20 * time.Minute).Format(wireTime), "productionAdmission": false}), 0600, 0)
	brokerConfig := filepath.Join(base, "broker.json")
	phaseDWrite(t, brokerConfig, phaseDJSON(c), 0600, 0)
	services := phaseD2InstallBroker(t, base, state, brokerConfig)
	defer services.close(t)
	daemonConfig := config.Config{ControlPlaneURL: server.URL + "/api/v1/runner-hosts", StateDir: snapshot.Journal, RuntimeEndpoint: x.Endpoint, CredentialFile: credentialPath, RequestTimeoutSeconds: 20, Execution: &config.Execution{Enabled: true, BrokerSocket: c.Socket, PolicyFile: policy, CustomCAFile: ca, CapabilitiesFile: filepath.Join(clientDir, "capabilities.json"), ImageRepository: x.ImageRepository, NetworkID: x.NetworkID, BootstrapRoot: x.ControllerBootstrapRoot, KeysDirectory: p.Keys, TrustRoots: p.Trust, ImageBundles: p.Trust, TrustProvisionedAt: p.Provisioned, Organization: "Neticora", Repository: "Neticora/project", Pool: p.Pool, PidsLimit: 128}}
	if _, err = config.Parse(phaseDJSON(daemonConfig)); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(clientDir, "config.json")
	phaseDWrite(t, configPath, phaseDJSON(daemonConfig), 0600, 10002)
	run := func(suffix string) error {
		unit := "neticora-f-" + filepath.Base(base) + "-" + suffix + ".service"
		body := fmt.Sprintf("[Service]\nType=oneshot\nUser=10002\nGroup=10002\nExecStart=%s --config %s --recovery broker-finalize\nCapabilityBoundingSet=\nAmbientCapabilities=\nSupplementaryGroups=\nNoNewPrivileges=yes\nPrivateDevices=yes\nProtectSystem=strict\nProtectHome=yes\nReadWritePaths=%s %s\nFileDescriptorStoreMax=0\nInaccessiblePaths=-/run/docker.sock -/run/containerd -/run/k3s/containerd -/run/runnerd09-docker.sock -%s\n", strconv.Quote(binary), strconv.Quote(configPath), snapshot.Journal, p.Keys, c.StateDirectory)
		mask, e := phaseE2ControllerPaths(p)
		if e != nil {
			t.Fatal(e)
		}
		body += mask
		services.install(t, unit, body)
		_, e = phaseD2Command("systemctl", "start", unit)
		trace, _ := phaseD2Command("journalctl", "-u", unit, "--no-pager", "-o", "cat")
		phaseDWrite(t, filepath.Join(state, unit+".log"), trace, 0600, 0)
		t.Log(string(trace))
		return e
	}
	if err = run("lost-ack"); err == nil || !lostAck {
		t.Fatal("lost ACK was not observed", err)
	}
	if err = run("resume"); err != nil {
		t.Fatal("native terminal recovery failed", err)
	}
	after, _ := os.ReadFile(credentialPath)
	if !bytes.Equal(after, credentialBefore) {
		t.Fatal("recovery rewrote identity")
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(snapshot.Journal, "journal.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var native, last, ack string
	var held int
	if err = db.QueryRow("select state,last_sequence,ack_sequence from executions where execution_id=?", f.start.Spec.ExecutionId).Scan(&native, &last, &ack); err != nil {
		t.Fatal(err)
	}
	db.QueryRow("select count(*) from reservations where released=0").Scan(&held)
	if native != "cleaned" || last != ack || held != 0 || !f.disposed {
		t.Fatal("final ACK/reservation incomplete", native, last, ack, held)
	}
	phaseDWrite(t, filepath.Join(state, "phase-f-native-finalization.json"), phaseDJSON(map[string]any{"purpose": "phase-f-native-finalization-engineering", "daemonBinary": binary, "nativeState": native, "lastSequence": last, "ackSequence": ack, "unreleasedReservations": held, "originalResourceId": history.Resource, "originalCommitments": len(history.Commits), "workloadRecreated": false, "credentialsUnchanged": true, "platformProvider": "durable protocol fixture; not production qualification", "productionAdmission": false}), 0600, 0)
	t.Log("actual installed runnerd/broker: original Kata disposed, CLEANED/final ACK persisted, reservation released; lost ACK reconciled without workload recreation")
}
func phaseFPrivate(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("fixture key")
	}
	v, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return v.(ed25519.PrivateKey)
}
