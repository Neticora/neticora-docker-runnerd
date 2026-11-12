//go:build !linux || !runnerd_qualification

package execution

import (
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"testing"
)

func TestOrdinaryServiceRejectsQualificationConfiguration(t *testing.T) {
	c := config.Config{Execution: &config.Execution{Enabled: true, BrokerSocket: "/run/broker.sock", Kata: &config.Kata{QualificationBindingFile: "/private/binding.json", QualificationAuthorityPin: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}
	if _, _, err := Open(c, nil, nil, func() bool { return false }); err == nil {
		t.Fatal("ordinary build selected qualification authority")
	}
}
