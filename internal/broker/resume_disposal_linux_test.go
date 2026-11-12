//go:build linux

package broker

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

func TestResumeDisposalUsesOnlyOriginalConsumedRemoval(t *testing.T) {
	e, runtime, base, key, now := physicalFixture(t)
	ctx := context.Background()
	resource := ""
	for revision, action := range []string{"CreateExecution", "StartExecution", "StopExecution"} {
		r, s, c := physicalAuthorization(t, e, base, key, action, revision, resource)
		o, err := e.Execute(ctx, r, s, c)
		if err != nil {
			t.Fatal(err)
		}
		if action == "CreateExecution" {
			resource = o.ID
		}
	}
	runtime.lostRemove = true
	r, s, c := physicalAuthorization(t, e, base, key, "RemoveExecution", 3, resource)
	if _, err := e.Execute(ctx, r, s, c); !errors.Is(err, ErrQuarantined) {
		t.Fatal(err)
	}
	e.now = func() time.Time { return now.Add(time.Minute) } // No renewed authority.
	q := Lookup{ExecutionID: r.ExecutionID, Generation: r.Generation, SpecHash: base.Grant.Binding.SpecHash, ResourceID: resource}
	if err := e.ResumeDisposal(ctx, q); err != nil {
		t.Fatal(err)
	}
	state, err := e.State(ctx, q, false)
	if !errors.Is(err, dockerengine.ErrAbsent) || state.Phase != "REMOVED" || state.Revision != "4" || runtime.removes != 1 {
		t.Fatal(state, err, runtime.removes)
	}
	if err = e.ResumeDisposal(ctx, q); err == nil {
		t.Fatal("completed intent reopened")
	}
	if runtime.removes != 1 {
		t.Fatal("Docker deletion repeated")
	}
}

func TestResumeDisposalRejectsForeignResourceAndMissingAuthority(t *testing.T) {
	for _, fault := range []string{"container-present", "replacement-name", "receipt-missing", "challenge-missing", "future-challenge", "wrong-resource"} {
		t.Run(fault, func(t *testing.T) {
			e, runtime, base, key, _ := physicalFixture(t)
			ctx := context.Background()
			resource := ""
			for revision, action := range []string{"CreateExecution", "StopExecution"} {
				r, s, c := physicalAuthorization(t, e, base, key, action, revision, resource)
				o, err := e.Execute(ctx, r, s, c)
				if err != nil {
					t.Fatal(err)
				}
				if action == "CreateExecution" {
					resource = o.ID
				}
			}
			runtime.lostRemove = true
			r, s, c := physicalAuthorization(t, e, base, key, "RemoveExecution", 2, resource)
			_, _ = e.Execute(ctx, r, s, c)
			q := Lookup{ExecutionID: r.ExecutionID, Generation: r.Generation, SpecHash: base.Grant.Binding.SpecHash, ResourceID: resource}
			switch fault {
			case "replacement-name":
				replacement := strings.Repeat("e", 64)
				for name, id := range runtime.names {
					if id == resource {
						runtime.names[name] = replacement
					}
				}
				runtime.objects[replacement] = dockerengine.Object{ID: replacement, State: "exited"}
			case "future-challenge":
				root, err := e.ledger.records("challenges")
				if err != nil {
					t.Fatal(err)
				}
				var challenge Challenge
				err = readRecord(root, r.OperationID, &challenge)
				if err == nil {
					challenge.Version = "future"
					err = e.ledger.writeRecord(root, r.OperationID, challenge)
				}
				root.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "container-present":
				runtime.objects[resource] = dockerengine.Object{ID: resource, State: "exited"}
			case "receipt-missing":
				if err := e.ledger.root.Remove(r.OperationID + ".json"); err != nil {
					t.Fatal(err)
				}
			case "challenge-missing":
				root, err := e.ledger.records("challenges")
				if err != nil {
					t.Fatal(err)
				}
				err = root.Remove(r.OperationID + ".json")
				root.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "wrong-resource":
				q.ResourceID = strings.Repeat("f", 64)
			}
			if err := e.ResumeDisposal(ctx, q); err == nil {
				t.Fatal("unproved removal resumed")
			}
			if runtime.removes != 1 {
				t.Fatal("Docker deletion repeated")
			}
		})
	}
}

func TestDisposedHandoffCrashAfterUnlinkReconcilesOriginalDirectory(t *testing.T) {
	m, p, _, _ := handoffFixture(t)
	if err := m.Prepare(p); err != nil {
		t.Fatal(err)
	}
	root, err := m.ledger.records("handoffs")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var record handoffRecord
	if err = readRecord(root, handoffID(p.Name), &record); err != nil {
		t.Fatal(err)
	}
	record.Phase = "DISPOSING"
	if err = m.ledger.writeRecord(root, handoffID(p.Name), record); err != nil {
		t.Fatal(err)
	}
	dir, err := m.root.OpenRoot(p.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err = dir.Remove("bootstrap.json"); err != nil {
		t.Fatal(err)
	}
	dir.Close()
	if err = m.root.Remove(p.Name); err != nil {
		t.Fatal(err)
	}
	if err = m.Dispose(p); err != nil {
		t.Fatal(err)
	}
	if err = m.CheckDisposed(p); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(m.root.Name()+"/"+p.Name, 0700); err != nil {
		t.Fatal(err)
	}
	if err = m.Dispose(p); err == nil {
		t.Fatal("reappeared directory accepted")
	}
}
