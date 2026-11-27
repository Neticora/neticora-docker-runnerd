package execution

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/stickycache"
)

type trustTestRemote struct {
	Remote
	allowed bool
	err     error
	calls   int
}

func (r *trustTestRemote) KataCacheAccess(context.Context, agent.ExecutionCursor) (bool, error) {
	r.calls++
	return r.allowed, r.err
}

func TestStickyCacheNeedsTrustedCommandAndRoutingProof(t *testing.T) {
	remote := &trustTestRemote{allowed: true}
	c := &Controller{Remote: remote}
	var cmd protocol.StartCommand
	cmd.Spec.Provider = "github"
	cmd.Spec.TrustClass = "trusted"
	cmd.Spec.IsolationProfile = "isolated"
	execution := func() agent.Execution {
		b, err := json.Marshal(cmd)
		if err != nil {
			t.Fatal(err)
		}
		return agent.Execution{Command: b}
	}
	if !c.cacheAuthorized(t.Context(), execution()) || remote.calls != 1 {
		t.Fatal("trusted provider authorization was lost")
	}
	cmd.Spec.TrustClass = "untrusted"
	if c.cacheAuthorized(t.Context(), execution()) || remote.calls != 1 {
		t.Fatal("untrusted command could request access")
	}
	cmd.Spec.TrustClass = "trusted"
	remote.allowed = false
	if c.cacheAuthorized(t.Context(), execution()) {
		t.Fatal("missing routing proof authorized cache")
	}
	remote.allowed, remote.err = true, errors.New("provider verification unavailable")
	if c.cacheAuthorized(t.Context(), execution()) {
		t.Fatal("transport failure authorized cache")
	}
}

func TestStickyCacheLegacyHeadsAreCleanupOnly(t *testing.T) {
	cache := newKataCache(stickycache.Policy{}, "installation", "tenant", "org/repo", "image")
	if cache.key == cache.legacyKey || !cache.ownsKey(cache.legacyKey) ||
		cache.ownsKey("unrelated") {
		t.Fatal("legacy cache cannot be reused and must remain available to owned cleanup")
	}
}
