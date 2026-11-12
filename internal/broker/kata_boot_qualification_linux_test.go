//go:build linux && runnerd_broker_qualification

package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	_ "modernc.org/sqlite"
)

// This qualifies preservation/denial after a real boot. It does not load a stale
// lab envelope as new admission or implement Kata boot recovery. All runtime
// access is read-only; historical planning is checked against the original hash.
func TestKataBootRetainedLab(t *testing.T) {
	input := os.Getenv("RUNNERD_E2_HELD_STATE")
	if input == "" {
		t.Skip("explicit held dedicated Kata fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root lab observer required")
	}
	marker, err := os.Lstat("/etc/neticora-runnerd-lab")
	if err != nil || hostfs.CheckAncestors("/etc") != nil {
		t.Fatal("marked disposable host required", err)
	}
	markerStat, ok := marker.Sys().(*syscall.Stat_t)
	if !ok || !marker.Mode().IsRegular() || marker.Mode().Perm()&0022 != 0 || markerStat.Uid != 0 {
		t.Fatal("unsafe lab marker")
	}

	if !strings.HasPrefix(input, "/var/lib/neticora-phase-d-") || filepath.Clean(input) != input {
		t.Fatal("wrong held fixture path")
	}
	raw, err := hostfs.ReadPrivate(input, MaxMessage)
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Purpose, Boot, MachineUUID, Ledger, Journal string
		BrokerConfig                                Config
		Hashes, KataArtifacts                       map[string]string
		ProductionAdmission                         bool
		PublicFixture                               struct {
			KataManifest  json.RawMessage
			KataProfileID string
			Scope         agent.StoreScope
			Start         protocol.StartCommand
		}
	}
	if json.Unmarshal(raw, &s) != nil || s.Purpose != "runnerd-d2-held-reboot" || s.ProductionAdmission || len(s.KataArtifacts) == 0 || s.BrokerConfig.Runtime == nil || s.BrokerConfig.Runtime.Kata == nil {
		t.Fatal("invalid held Kata evidence")
	}
	bootRaw, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	boot := strings.TrimSpace(string(bootRaw))
	machine, _ := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if len(boot) != 36 || boot == s.Boot || !strings.EqualFold(strings.TrimSpace(string(machine)), s.MachineUUID) {
		t.Fatal("same machine and changed boot required")
	}
	unchanged := func() {
		for _, files := range []map[string]string{s.Hashes, s.KataArtifacts} {
			for name, want := range files {
				f, e := os.Open(name)
				if e != nil {
					t.Fatal("retained evidence missing", name, e)
				}
				h := sha256.New()
				_, e = io.Copy(h, f)
				f.Close()
				if e != nil || hex.EncodeToString(h.Sum(nil)) != want {
					t.Fatal("original Kata identity/data changed", name, e)
				}
			}
		}
	}
	unchanged()
	defer unchanged()
	l, err := OpenLedger(s.Ledger)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c := s.BrokerConfig
	x := c.Runtime
	engine, err := dockerengine.OpenReadOnly(x.Endpoint, c.Scope.InstallationID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	endpoint, err := engine.Probe(context.Background())
	if err != nil || endpoint == c.Scope.EndpointIdentity {
		t.Fatal("changed runtime peer must be observed", err)
	}
	var m katalinux.Manifest
	if json.Unmarshal(s.PublicFixture.KataManifest, &m) != nil || m.Storage.Block == nil {
		t.Fatal("historical Kata profile absent")
	}
	id, err := katalinux.ProfileID(m)
	if err != nil || id != s.PublicFixture.KataProfileID {
		t.Fatal("historical profile identity differs")
	}
	settings := standardlinux.Settings{ImageRepository: x.ImageRepository, NetworkID: x.NetworkID, BootstrapRoot: x.BootstrapRoot, RunnerUID: int(c.ControllerUID), PidsLimit: x.PidsLimit}
	profile := &katalinux.Profile{ID: id, Manifest: m, Base: settings, EvidenceDirectory: x.Kata.EvidenceDirectory, JournalDirectory: x.Kata.JournalDirectory}
	e := &physicalExecutor{ledger: l, runtime: engine, scope: c.Scope, settings: settings, boot: boot, now: time.Now, kata: &protectedKata{profile: profile, engine: engine}}
	start := s.PublicFixture.Start
	q := Lookup{ExecutionID: start.Spec.ExecutionId, Generation: start.Generation, SpecHash: start.Spec.SpecHash}
	resources, err := l.records("resources")
	if err != nil {
		t.Fatal(err)
	}
	var original physicalRecord
	b := e.scope
	b.ExecutionID = q.ExecutionID
	b.Generation = q.Generation
	err = readRecord(resources, recordID(b), &original)
	resources.Close()
	if err != nil || original.Spec.IsolationProfile != "isolated" || original.Pending == "" || original.ResourceID == "" {
		t.Fatal("original pending Kata ownership not retained", err)
	}
	q.ResourceID = original.ResourceID
	state, err := e.State(context.Background(), q, true)
	if !errors.Is(err, ErrQuarantined) {
		t.Fatal("Kata boot uncertainty inferred completion", state.Phase, err)
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(private)
	if _, err = e.IssueBootChallenge(context.Background(), q, private); !errors.Is(err, ErrQuarantined) {
		t.Fatal("Docker boot challenge offered for Kata", err)
	}
	// The operation is categorically unsupported for this original Kata record,
	// including a controller presenting a Docker-only cleanup certificate tuple.
	certificate := SignedBootCertificate{Certificate: BootCertificate{Version: BootRecoveryVersion, Operation: "RecoverBootCleanup", Challenge: SignedBootChallenge{Challenge: BootChallenge{Binding: original.Binding, ResourceID: original.ResourceID}}}}
	if err = e.RecoverBoot(context.Background(), certificate); !errors.Is(err, ErrQuarantined) {
		t.Fatal("Docker-only recovery reached Kata effects", err)
	}

	slotsRaw, err := os.ReadFile(filepath.Join(profile.EvidenceDirectory, "block-slots.json"))
	if err != nil {
		t.Fatal(err)
	}
	var slots struct {
		Record struct {
			Active map[string]struct {
				Record katalinux.BlockRecord `json:"record"`
			} `json:"active"`
		} `json:"record"`
	}
	if json.Unmarshal(slotsRaw, &slots) != nil {
		t.Fatal("invalid original block index")
	}
	block, exists := slots.Record.Active[original.Name]
	if !exists || block.Record.Phase == "released" || block.Record.FileInode == 0 {
		t.Fatal("original block reservation lost")
	}
	info, err := os.Stat(filepath.Join(m.Storage.Block.Pool.Root, original.Name+".raw"))
	if err != nil {
		t.Fatal(err)
	}
	physical, ok := info.Sys().(*syscall.Stat_t)
	if !ok || physical.Ino != block.Record.FileInode || uint64(info.Size()) != block.Record.Bytes {
		t.Fatal("original raw disk replaced")
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(s.Journal, "journal.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var native string
	var reserved int
	err = db.QueryRow("SELECT state FROM executions WHERE execution_id=?", start.Spec.ExecutionId).Scan(&native)
	if err == nil {
		err = db.QueryRow("SELECT count(*) FROM reservations WHERE released=0").Scan(&reserved)
	}
	db.Close()
	if err != nil || native == "cleaned" || reserved != 1 {
		t.Fatal("uncertain boot released native reservation", native, reserved, err)
	}
	proof := map[string]any{"purpose": "runnerd-e2-kata-boot-quarantine", "fromBoot": s.Boot, "toBoot": boot, "resourceId": original.ResourceID, "pendingOperationId": original.Pending, "name": original.Name, "profile": profile.ID, "blockPhase": block.Record.Phase, "originalFileDevice": block.Record.FileDevice, "observedFileDevice": uint64(physical.Dev), "fileInode": physical.Ino, "blockReservationRetained": true, "unreleasedReservations": reserved, "nativeState": native, "originalArtifactsUnchanged": true, "dockerOnlyRecoveryRejected": true, "automaticKataRecoveryQualified": false, "productionAdmission": false}
	raw, _ = json.MarshalIndent(proof, "", "  ")
	if err = os.WriteFile(filepath.Join(filepath.Dir(input), "kata-boot-quarantine-"+boot+".json"), append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("real boot/peer change: original Kata disk, pool/index, consumed operation and native reservation retained; Docker-only recovery rejected; automatic recovery NOT qualified")
}
