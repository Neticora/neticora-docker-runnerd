//go:build linux && runnerd_connection_qualification

package journal

// This fixture is compiled ONLY into a qualification test executable. It never
// ships in Runnerd. It seeds synthetic native history without a runtime effect,
// ACK RPC, admission toggle or fabricated execution-recovery checkpoint.
import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
)

func TestRunnerd08SeedNativeConnectionFixture(t *testing.T) {
	path := os.Getenv("RUNNERD_CONNECTION_FIXTURE_STATE")
	mode := os.Getenv("RUNNERD_CONNECTION_FIXTURE_MODE")
	if path == "" {
		t.Skip("explicit disposable VM fixture only")
	}
	hostname, _ := os.Hostname()
	if hostname != "runnerd08-resync-lab" || os.Geteuid() == 0 || (path != "/var/lib/neticora-runnerd" && path != "/var/lib/neticora-runnerd-resync-negative") || (mode != "completed" && mode != "unresolved") {
		t.Fatal("disposable VM/service identity required")
	}
	active, _ := exec.Command("systemctl", "is-active", "neticora-runnerd").Output()
	if strings.TrimSpace(string(active)) == "active" {
		t.Fatal("stop original service before fixture writes")
	}
	raw, err := os.ReadFile("/etc/neticora-runnerd/identity.json")
	if err != nil {
		t.Fatal(err)
	}
	var cred struct {
		InstallationID string                `json:"installationId"`
		TenantID       string                `json:"tenantId"`
		Endpoint       string                `json:"endpointIdentity"`
		Identity       protocol.HostIdentity `json:"identity"`
	}
	if json.Unmarshal(raw, &cred) != nil {
		t.Fatal("original identity unavailable")
	}
	clear(raw)
	scope := agent.StoreScope{InstallationID: cred.InstallationID, TenantID: cred.TenantID, HostID: cred.Identity.HostId, SessionEpoch: cred.Identity.SessionEpoch, EndpointIdentity: cred.Endpoint}
	ctx := context.Background()
	s, err := OpenRecovery(ctx, path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	suffix := "connection-history-fixture"
	if mode == "unresolved" {
		suffix = "connection-blocked-fixture"
	}
	start := storetest.Start(t, suffix)
	doc := storetest.Object(t, start)
	spec := doc["spec"].(map[string]any)
	identity := agent.Identity{InstallationID: scope.InstallationID, TenantID: scope.TenantID, HostID: scope.HostID, ExecutionID: spec["executionId"].(string), Generation: spec["generation"].(string), SpecHash: spec["specHash"].(string), AttemptID: spec["attemptId"].(string)}
	idRaw, _ := json.Marshal(identity)
	scopeRaw, _ := json.Marshal(scope)
	budget, _ := json.Marshal(spec["resources"])
	err = s.transaction(ctx, false, false, false, func(ctx context.Context, tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM executions WHERE execution_id=?", identity.ExecutionID).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			return agent.ErrConflict
		}
		state, terminal, sequence, released := "accepted", false, padded("0"), false
		if mode == "completed" {
			state = "cleaned"
			terminal = true
			sequence = padded("1")
			released = true
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO executions(execution_id,generation,identity,session_epoch,endpoint_identity,attempt_id,command_id,command,state,runtime_terminal,last_sequence,ack_sequence) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", identity.ExecutionID, identity.Generation, idRaw, scope.SessionEpoch, scope.EndpointIdentity, identity.AttemptID, doc["commandId"], start, state, terminal, sequence, sequence)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO commands(command_id,payload_hash,execution_id,generation,kind,payload) VALUES(?,?,?,?,?,?)", doc["commandId"], doc["payloadHash"], identity.ExecutionID, identity.Generation, "start", start); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO reservations(execution_id,generation,resources,released) VALUES(?,?,?,?)", identity.ExecutionID, identity.Generation, budget, released); err != nil {
			return err
		}
		if mode == "completed" {
			event := storetest.Object(t, storetest.Event(t, start, 1, "cleaned"))
			proof, _ := json.Marshal(map[string]any{"fixture": "never-submitted-synthetic-history", "observedAt": time.Now().UTC().Format(time.RFC3339Nano)})
			if _, err = tx.ExecContext(ctx, "INSERT INTO outbox_events(execution_id,generation,sequence,event_id,payload_hash,payload) VALUES(?,?,?,?,?,NULL)", identity.ExecutionID, identity.Generation, padded("1"), event["eventId"], event["payloadHash"]); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO cleanup_tasks(execution_id,generation,complete,evidence) VALUES(?,?,1,?)", identity.ExecutionID, identity.Generation, proof); err != nil {
				return err
			}
		}
		var existing []byte
		if err = tx.QueryRowContext(ctx, "SELECT scope FROM metadata WHERE singleton=1").Scan(&existing); err != nil {
			return err
		}
		if len(existing) == 0 {
			_, err = tx.ExecContext(ctx, "UPDATE metadata SET scope=? WHERE singleton=1", scopeRaw)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Health(ctx).Ready {
		t.Fatal("fixture fabricated execution readiness")
	}
	t.Logf("synthetic %s native fixture retained at %s; original journal=%s; execution recovery remains fenced", mode, path, s.Health(ctx).JournalID)
}
