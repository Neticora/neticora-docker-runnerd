//go:build !linux || !runnerd_qualification

package execution

import (
	"errors"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/stickycache"
)

func TestOrdinaryServiceRejectsQualificationConfiguration(t *testing.T) {
	c := config.Config{RuntimeEndpoint: "unix:///run/docker.sock", Execution: &config.Execution{Enabled: true, Kata: &config.Kata{
		StickyCache:               &stickycache.Policy{VolumeGroup: "vg", ThinPool: "pool", PoolUUID: "uuid", VolumeBytes: 1 << 30, MaxDataPercent: 60, MaxMetaPercent: 60, Retain: 1},
		QualificationBindingFile:  "/private/binding.json",
		QualificationAuthorityPin: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}}}
	if !c.StandaloneExecution() {
		t.Fatal("fixture does not select standalone execution")
	}
	if _, _, err := Open(c, nil, nil, func() bool { return false }); err == nil || errors.Is(err, ErrKataOnly) {
		t.Fatal("ordinary build selected qualification authority or rejected the wrong path", err)
	}
}
