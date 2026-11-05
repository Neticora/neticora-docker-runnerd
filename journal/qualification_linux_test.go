//go:build linux && runnerd_qualification

package journal

// Lab-only test binary. No crash hook, synthetic authority, or fault-control
// environment variable is linked into the shipping daemon.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
)

type labFact struct {
	Kind     string `json:"kind"`
	Name     string `json:"name,omitempty"`
	Sequence string `json:"sequence,omitempty"`
	Hash     string `json:"hash,omitempty"`
	Phase    string `json:"phase,omitempty"`
	Stage    string `json:"stage,omitempty"`
}

func labDirectory(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("RUNNERD08_STATE")
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal("disposable lab required")
	}
	if !strings.HasPrefix(dir, "/var/tmp/runnerd08-") || filepath.Clean(dir) != dir {
		t.Fatal("isolated lab state required")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private existing lab state required")
	}
	return dir
}

func emitLab(t *testing.T, fact labFact) {
	t.Helper()
	raw, err := json.Marshal(fact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fmt.Printf("RUNNERD08 %s\n", raw); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerd08PowerWriter(t *testing.T) {
	if os.Getenv("RUNNERD08_POWER_WRITER") != "1" {
		t.Skip("external power-cut coordinator required")
	}
	dir := labDirectory(t)
	ctx := context.Background()
	s, err := OpenRecovery(ctx, dir, testOptions(Options{}))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	storetest.Reconcile(t, s, storetest.Scope, "1")
	accept := func(name string) []byte {
		command := storetest.Start(t, name)
		r, err := s.AcceptCommand(ctx, storetest.Scope, command)
		if err != nil {
			t.Fatal(err)
		}
		emitLab(t, labFact{Kind: "receipt", Name: name, Hash: r.PayloadHash})
		return command
	}
	accept("baseline")
	phase, stage := os.Getenv("RUNNERD08_PHASE"), os.Getenv("RUNNERD08_STAGE")
	if stage != "before-commit" && stage != "after-commit" && stage != "after-anchor" {
		t.Fatal("explicit durability boundary required")
	}
	command := storetest.Start(t, "candidate")
	if phase != "receipt" {
		command = accept("candidate")
	}
	pending := storetest.Event(t, command, 1, "cleanup-pending")
	if phase == "cleaned" {
		if err = s.RequireCleanup(ctx, storetest.Scope, pending); err != nil {
			t.Fatal(err)
		}
		var event struct {
			PayloadHash string `json:"payloadHash"`
		}
		_ = json.Unmarshal(pending, &event)
		emitLab(t, labFact{Kind: "event", Name: "candidate", Sequence: "1", Hash: event.PayloadHash})
	}
	if phase == "checkpoint" {
		for i := 1; i <= 512; i++ {
			event := storetest.Event(t, command, uint64(i), "running")
			if err = s.RecordObservation(ctx, storetest.Scope, event); err != nil {
				t.Fatal(err)
			}
			var value struct {
				PayloadHash string `json:"payloadHash"`
			}
			_ = json.Unmarshal(event, &value)
			emitLab(t, labFact{Kind: "event", Name: "candidate", Sequence: fmt.Sprint(i), Hash: value.PayloadHash})
		}
		emitLab(t, labFact{Kind: "cut-ready", Phase: phase, Stage: "checkpoint-loop"})
		// Repeated real TRUNCATE checkpoints; external power removal is timed
		// during this loop, without claiming a specific device flush boundary.
		for {
			if _, err = s.Checkpoint(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	s.fault = func(point string) error {
		if point == stage {
			emitLab(t, labFact{Kind: "cut-ready", Phase: phase, Stage: stage})
			for {
				time.Sleep(time.Hour)
			}
		}
		return nil
	}
	switch phase {
	case "receipt":
		_, err = s.AcceptCommand(ctx, storetest.Scope, command)
	case "intent":
		err = s.PutStartIntent(ctx, storetest.Scope, storetest.Intent(t, command))
	case "event":
		err = s.RecordObservation(ctx, storetest.Scope, storetest.Event(t, command, 1, "running"))
	case "cleanup":
		err = s.RequireCleanup(ctx, storetest.Scope, pending)
	case "cleaned":
		event := storetest.Event(t, command, 2, "cleaned")
		err = s.CompleteCleanup(ctx, storetest.Scope, event, storetest.Proof(t, event, "2"))
	default:
		t.Fatal("unsupported phase")
	}
	t.Fatal("power-cut boundary missed", err)
}

func TestRunnerd08PowerRecovery(t *testing.T) {
	if os.Getenv("RUNNERD08_POWER_VERIFY") != "1" {
		t.Skip("external power-cut ledger required")
	}
	dir := labDirectory(t)
	ctx := context.Background()
	raw, err := os.ReadFile(filepath.Join(dir, "external-ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	var facts []labFact
	if json.Unmarshal(raw, &facts) != nil || len(facts) == 0 {
		t.Fatal("external durable ledger missing")
	}
	s, err := OpenRecovery(ctx, dir, testOptions(Options{}))
	if err != nil {
		t.Fatal("acknowledged state could not recover", err)
	}
	defer s.Close()
	if s.Health(ctx).Ready {
		t.Fatal("cold boot restored admission without inventory")
	}
	for _, fact := range facts {
		var hash string
		switch fact.Kind {
		case "receipt":
			err = s.db.QueryRowContext(ctx, "SELECT payload_hash FROM commands WHERE command_id=?", "cmd-"+fact.Name).Scan(&hash)
		case "event":
			err = s.db.QueryRowContext(ctx, "SELECT payload_hash FROM outbox_events WHERE execution_id=? AND sequence=?", "exec-"+fact.Name, fmt.Sprintf("%020s", fact.Sequence)).Scan(&hash)
		default:
			continue
		}
		if err != nil || hash != fact.Hash {
			t.Fatal("acknowledged receipt/fact lost or altered", fact.Kind, fact.Name, fact.Sequence)
		}
	}
	var invalid int
	err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM executions e JOIN reservations r USING(execution_id,generation)
 WHERE (e.state='cleaned') != (r.released=1) OR (e.state='cleaned' AND NOT EXISTS
 (SELECT 1 FROM outbox_events o WHERE o.execution_id=e.execution_id AND o.generation=e.generation AND json_extract(o.payload,'$.observation.state')='cleaned'))`).Scan(&invalid)
	if err != nil || invalid != 0 {
		t.Fatal("cleanup/reservation atomicity violated", err)
	}
	var duplicates int
	err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM (SELECT execution_id,generation,count(*) n FROM reservations GROUP BY execution_id,generation HAVING n>1)").Scan(&duplicates)
	if err != nil || duplicates != 0 {
		t.Fatal("duplicate physical reservation", err)
	}
	emitLab(t, labFact{Kind: "recovery-verified"})
}

func TestRunnerd08RealENOSPC(t *testing.T) {
	if os.Getenv("RUNNERD08_ENOSPC") != "1" {
		t.Skip("isolated loop filesystem required")
	}
	dir := labDirectory(t)
	ctx := context.Background()
	var fs syscall.Statfs_t
	if syscall.Statfs(dir, &fs) != nil || uint64(fs.Type) != 0xef53 || fs.Blocks*uint64(fs.Bsize) > 256<<20 {
		t.Fatal("bounded disposable ext4 volume required")
	}
	s, err := OpenRecovery(ctx, dir, testOptions(Options{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	storetest.Reconcile(t, s, storetest.Scope, "1")
	command := storetest.Start(t, "disk")
	original, err := s.AcceptCommand(ctx, storetest.Scope, command)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "exclusive-pressure")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	buffer := make([]byte, 1<<20)
	for {
		_, err = f.Write(buffer)
		if err != nil {
			break
		}
	}
	_ = f.Close()
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatal("actual ENOSPC not observed", err)
	}
	if _, err = s.AcceptCommand(ctx, storetest.Scope, storetest.Start(t, "new")); err == nil {
		t.Fatal("full disk admitted work")
	}
	if replay, err := s.Receipt(ctx, storetest.Scope, command); err != nil || replay.PayloadHash != original.PayloadHash {
		t.Fatal("pressure lost durable receipt", err)
	}
	// Recovery writes must either commit their complete fact or fail closed.
	writeErr := s.RequireCleanup(ctx, storetest.Scope, storetest.Event(t, command, 1, "cleanup-pending"))
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenRecovery(ctx, dir, testOptions(Options{}))
	if err != nil {
		t.Fatal(err)
	}
	if count(t, s, "commands") != 1 || count(t, s, "reservations") != 1 {
		t.Fatal("pressure changed ownership")
	}
	var released int
	if err = s.db.QueryRowContext(ctx, "SELECT released FROM reservations").Scan(&released); err != nil || released != 0 {
		t.Fatal("pressure freed physical reservation", err)
	}
	if writeErr == nil && count(t, s, "outbox_events") != 1 {
		t.Fatal("successful recovery write lost its fact")
	}
	emitLab(t, labFact{Kind: "real-enospc-verified"})
}
