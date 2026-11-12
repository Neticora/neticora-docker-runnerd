//go:build linux && runnerd_broker_qualification && !runnerd_qualification

package execution

import (
	"encoding/json"
	"github.com/Neticora/neticora-docker-runnerd/internal/broker"
	"os"
	"testing"
)

func phaseEKataSpec(t *testing.T, _ map[string]any, _ string) (json.RawMessage, string) {
	if os.Getenv("RUNNERD_PHASE_E_SEED") != "" {
		t.Fatal("Kata qualification tag required")
	}
	return nil, ""
}
func phaseEKataBroker(t *testing.T, _ *broker.Config, _ json.RawMessage, _ []byte, _ string) {
	t.Fatal("Kata qualification tag required")
}
func phaseEKataController(*testing.T, *Controller, phaseDPublic) {}
