//go:build linux && runnerd_broker_qualification

package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

type bootInventoryFault struct{ *dockerengine.Engine }

func (f bootInventoryFault) Inventory(ctx context.Context) ([]string, error) {
	ids, err := f.Engine.Inventory(ctx)
	if err != nil {
		return ids, err
	}
	return ids, dockerengine.ErrUnavailable
}

// Uses an existing retained D2 installation, never creates a replacement. The
// issuer is the ORIGINAL disposable fixture key; platform/provider are fixtures.
// Actual PostgreSQL issuer/disposal transactions are qualified separately.
func TestBootRecoveryRetainedDockerLab(t *testing.T) {
	input := os.Getenv("RUNNERD_BOOT_RECOVERY_EVIDENCE")
	if input == "" {
		t.Skip("explicit retained disposable fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(input, "/var/lib/neticora-phase-d-") || filepath.Clean(input) != input {
		t.Fatal("wrong fixture path")
	}
	raw, err := hostfs.ReadPrivate(input, MaxMessage)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		Purpose             string            `json:"purpose"`
		Boot                string            `json:"boot"`
		Ledger              string            `json:"ledger"`
		BrokerConfig        Config            `json:"brokerConfig"`
		Hashes              map[string]string `json:"hashes"`
		ProductionAdmission bool              `json:"productionAdmission"`
	}
	if json.Unmarshal(raw, &snapshot) != nil || snapshot.Purpose != "runnerd-d2-held-reboot" || snapshot.ProductionAdmission {
		t.Fatal("wrong evidence")
	}
	unchanged := func() {
		for name, want := range snapshot.Hashes {
			data, err := os.ReadFile(name)
			sum := sha256.Sum256(data)
			if err != nil || hex.EncodeToString(sum[:]) != want {
				t.Fatalf("original ownership changed: %s %v", name, err)
			}
		}
	}
	unchanged()
	defer unchanged()
	ledger, err := OpenLedger(snapshot.Ledger)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	c := snapshot.BrokerConfig
	issuerPEM, err := hostfs.ReadPrivate(filepath.Join(filepath.Dir(snapshot.Ledger), "fixture-private", "issuer.pem"), 16384)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(issuerPEM)
	block, _ := pem.Decode(issuerPEM)
	if block == nil {
		t.Fatal("issuer fixture")
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	issuer, ok := value.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("issuer type")
	}
	pinned, err := base64.StdEncoding.DecodeString(c.ExecutionGrantPublicKey)
	if err != nil || !issuer.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(pinned)) {
		t.Fatal("fixture issuer is not original pinned issuer")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	currentBoot := strings.TrimSpace(string(boot))
	if currentBoot == snapshot.Boot {
		t.Fatal("boot boundary required")
	}
	// Recreate only the empty protected tmpfs parent; the original handoff leaf
	// must remain absent. No original source or bootstrap bytes are regenerated.
	if err = os.MkdirAll(c.Runtime.BootstrapRoot, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := hostfs.OpenState(c.Runtime.BootstrapRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	engine, err := dockerengine.Open(c.Runtime.Endpoint, c.Scope.InstallationID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	e := &physicalExecutor{ledger: ledger, runtime: engine, key: pinned, scope: c.Scope, boot: currentBoot, now: time.Now, settings: standardlinux.Settings{ImageRepository: c.Runtime.ImageRepository, NetworkID: c.Runtime.NetworkID, BootstrapRoot: c.Runtime.BootstrapRoot, RunnerUID: int(c.ControllerUID), PidsLimit: c.Runtime.PidsLimit}, handoffs: &handoffManager{ledger: ledger, root: root, boot: currentBoot}}
	resources, err := ledger.records("resources")
	if err != nil {
		t.Fatal(err)
	}
	directory, err := resources.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	files, err := directory.ReadDir(-1)
	directory.Close()
	if err != nil || len(files) != 1 {
		t.Fatal("exact original physical record required", err)
	}
	var original physicalRecord
	raw, err = resources.ReadFile(files[0].Name())
	resources.Close()
	if err != nil || json.Unmarshal(raw, &original) != nil {
		t.Fatal(err)
	}
	if original.Spec.IsolationProfile == "isolated" {
		if os.Getenv("RUNNERD_BOOT_RECOVERY_KATA") != "1" || len(original.KataOrigin) == 0 {
			t.Fatal("explicit original Kata origin required")
		}
		release, err := katalinux.ClaimBrokerRecoveryDirectory(c.Runtime.Kata.EvidenceDirectory)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		e.recoveryOnly = true
		e.restoreKata = func(raw json.RawMessage) (kataBootLifecycle, error) {
			profile, err := katalinux.RestoreBrokerCleanup(raw, e.settings, c.Scope.InstallationID, c.Scope.HostID)
			if err != nil {
				return nil, err
			}
			if profile.EvidenceDirectory != c.Runtime.Kata.EvidenceDirectory || profile.JournalDirectory != c.Runtime.Kata.JournalDirectory {
				return nil, ErrQuarantined
			}
			if err = profile.RecoverProbe(context.Background(), engine); err != nil {
				return nil, err
			}
			return &protectedKata{profile: profile, engine: engine}, nil
		}
	}
	q := Lookup{ExecutionID: original.Binding.ExecutionID, Generation: original.Binding.Generation, SpecHash: original.Binding.SpecHash, ResourceID: original.ResourceID}
	_, disposal, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(disposal.Public())
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(filepath.Dir(input), "boot-recovery-disposal-public-"+currentBoot+".pem")
	if err = os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0600); err != nil {
		t.Fatal(err)
	}
	ch, err := e.IssueBootChallenge(context.Background(), q, disposal)
	if err != nil {
		t.Fatal(err)
	}
	cert := BootCertificate{Version: BootRecoveryVersion, Operation: "RecoverBootCleanup", ID: bootHash(ch), Challenge: ch, NotBefore: time.Now().UTC().Format(time.RFC3339Nano), ExpiresAt: ch.Challenge.ExpiresAt}
	a := SignedBootCertificate{Certificate: cert, Signature: signBoot(BootRecoveryDomain, cert, issuer)}
	if prior, priorErr := e.bootRecord(original); priorErr == nil && prior.Authority.Certificate.Challenge.Challenge.ToEndpointIdentity == ch.Challenge.ToEndpointIdentity {
		a = prior.Authority
		cert = a.Certificate
		ch = cert.Challenge
	}
	mode := os.Getenv("RUNNERD_BOOT_RECOVERY_MODE")
	if mode == "prepare" {
		e.runtime = bootInventoryFault{engine}
	}
	err = e.RecoverBoot(context.Background(), a)
	if mode == "prepare" {
		if err == nil {
			t.Fatal("inventory ambiguity must retain recovery")
		}
		record, recordErr := e.bootRecord(original)
		if recordErr != nil || record.Phase != "PENDING" {
			t.Fatal(record, recordErr)
		}
		t.Log("original cleanup authority durably accepted; injected inventory failure retains pending recovery and native reservation")
	} else if mode == "complete" {
		if err != nil {
			t.Fatal(err)
		}
		state, stateErr := e.State(context.Background(), q, true)
		if !errors.Is(stateErr, dockerengine.ErrAbsent) || state.Phase != "RECOVERY_DISPOSED" {
			t.Fatal(state, stateErr)
		}
		observed := time.Now().UTC().Truncate(time.Millisecond)
		challenge := DisposalChallenge{Version: DisposalVersion, Binding: original.Binding, ResourceID: original.ResourceID, OperationIDs: ch.Challenge.OperationIDs, Nonce: ch.Challenge.Nonce, NotBefore: observed.Format(time.RFC3339Nano), ExpiresAt: observed.Add(time.Minute).Format(time.RFC3339Nano), RecoveryID: cert.ID}
		proof, proofErr := e.Attest(context.Background(), SignedDisposalChallenge{Challenge: challenge, Signature: signBoot(DisposalChallengeDomain, challenge, issuer)}, disposal)
		if proofErr != nil {
			t.Fatal(proofErr)
		}
		raw, _ := json.MarshalIndent(proof, "", "  ")
		output := filepath.Join(filepath.Dir(input), "boot-recovery-disposal-"+currentBoot+".json")
		file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = file.Write(raw)
		if err == nil {
			err = file.Sync()
		}
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !verifyBoot(DisposalDomain, proof.Disposal, proof.Signature, disposal.Public().(ed25519.PublicKey)) {
			t.Fatal("disposal signature invalid")
		}
		t.Log("original ambiguous create physically resolved; original records and native reservation unchanged; fresh independent disposal proof", output)
	} else {
		t.Fatal("explicit prepare or complete mode required")
	}
	t.Log("current boot", currentBoot, "previous recovery", ch.Challenge.PreviousRecoveryID, "certificate", cert.ID)
}
