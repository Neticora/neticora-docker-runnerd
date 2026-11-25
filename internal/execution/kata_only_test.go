package execution

import (
	"errors"
	"testing"

	"github.com/Neticora/neticora-docker-runnerd/internal/config"
)

func TestServiceRejectsRetiredLaunchPaths(t *testing.T) {
	for _, execution := range []config.Execution{
		{Enabled: true},
		{Enabled: true, BrokerSocket: "/run/legacy-broker.sock", Kata: &config.Kata{}},
		{Enabled: true, Kata: &config.Kata{ObserverSocket: "/run/legacy-observer.sock"}},
	} {
		c := config.Config{Execution: &execution, RuntimeEndpoint: "unix:///run/docker.sock"}
		if _, _, err := Open(c, nil, nil, nil); !errors.Is(err, ErrKataOnly) {
			t.Fatal("retired execution path reached service initialization", err)
		}
	}
}
