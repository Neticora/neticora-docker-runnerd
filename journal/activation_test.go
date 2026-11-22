package journal

import (
	"context"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/agent/storetest"
)

func TestActivationPreservesOriginalSettledScopeAndRejectsOutstandingWork(t *testing.T) {
	ctx := context.Background()
	s := recovery(t, privateDir(t), Options{})
	if err := s.VerifyActivationScope(ctx, storetest.Scope); err != nil {
		t.Fatal("empty original journal rejected", err)
	}
	storetest.Reconcile(t, s, storetest.Scope, "1")
	revision := s.Health(ctx).Revision
	if err := s.VerifyActivationScope(ctx, storetest.Scope); err != nil {
		t.Fatal(err)
	}
	other := storetest.Scope
	other.HostID = "another-host"
	if err := s.VerifyActivationScope(ctx, other); err == nil {
		t.Fatal("different installation history accepted")
	}
	other = storetest.Scope
	other.SessionEpoch = "2"
	if err := s.VerifyActivationScope(ctx, other); err == nil {
		t.Fatal("new session inferred without recovery")
	}
	if s.Health(ctx).Revision != revision {
		t.Fatal("activation diagnostic wrote a checkpoint")
	}
	if _, err := s.AcceptCommand(ctx, storetest.Scope, storetest.Start(t, "activation")); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyActivationScope(ctx, storetest.Scope); err == nil {
		t.Fatal("activation discarded pending work")
	}
}
