//go:build linux

package workerboundary

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestPublicIdentityCannotDischargeLifetime(t *testing.T) {
	boot, e := bootID()
	if e != nil {
		t.Fatal(e)
	}
	forged := Identity{PID: os.Getpid(), Start: "1", Boot: boot, PIDNamespaceInode: 1, MountNamespaceInode: 2}
	// A mismatched or missing public PID is not evidence that a verified init
	// ever existed. JSON cannot recreate the protected ownership capability.
	raw, e := json.Marshal(forged)
	if e != nil {
		t.Fatal(e)
	}
	var public Identity
	if e = json.Unmarshal(raw, &public); e != nil {
		t.Fatal(e)
	}
	if public.CheckRetired() == nil {
		t.Fatal("public JSON invented a retired original namespace")
	}
	if public.Retire(context.Background()) == nil {
		t.Fatal("public JSON acquired signaling authority")
	}
}
func TestAmbiguousIntentNeverAdoptsSocketOrReleases(t *testing.T) {
	b := Binding{InstallationID: "fixture-installation", TenantID: "fixture-tenant", HostID: "fixture-host", SessionEpoch: "1", Endpoint: "fixture-endpoint", ExecutionID: "fixture-execution", Generation: "1", SpecHash: strings.Repeat("a", 64), Profile: "fixture-profile", Name: "nrd-" + strings.Repeat("b", 64)}
	g := Registry{Directory: t.TempDir()}
	if err := os.Chmod(g.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	r := Record{Version: RecordVersion, Binding: b, CreationOperationID: strings.Repeat("c", 64), Owner: strings.Repeat("d", 64), HelperSHA256: strings.Repeat("e", 64), PolicySHA256: strings.Repeat("f", 64), Phase: "INTENT"}
	if e := g.write(r); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(g.Directory + "/" + b.Name + ".domain.json")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = g.CheckRetired(b, strings.Repeat("1", 64)); e == nil {
		t.Fatal("unverified intent became retirement evidence")
	}
	if _, e = g.Retire(context.Background(), b, strings.Repeat("1", 64)); e == nil {
		t.Fatal("unknown namespace adopted for cleanup")
	}
	after, e := os.ReadFile(g.Directory + "/" + b.Name + ".domain.json")
	if e != nil || string(before) != string(after) {
		t.Fatal("ambiguous ownership was rewritten", e)
	}
	foreign := b
	foreign.Generation = "2"
	if _, e = g.Load(foreign); e == nil {
		t.Fatal("stale generation reused lifetime ownership")
	}
	foreign = b
	foreign.SpecHash = strings.Repeat("0", 64)
	if _, e = g.Load(foreign); e == nil {
		t.Fatal("substituted execution adopted lifetime ownership")
	}
	if _, e = g.Quarantine(b); e != nil {
		t.Fatal(e)
	}
	held, e := g.Load(b)
	if e != nil || !held.Quarantined || held.Phase != "INTENT" || !held.SameOriginal(r) {
		t.Fatal("quarantine lost original phase or ownership", e)
	}
	if _, e = g.Retire(context.Background(), b, strings.Repeat("1", 64)); e == nil {
		t.Fatal("quarantine invented retirement authority")
	}
}
