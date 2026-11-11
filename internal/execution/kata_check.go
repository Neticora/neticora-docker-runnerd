package execution

import (
	"context"
	"encoding/json"
	"os"

	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

// CheckKata is read-only: it verifies an ALREADY independently qualified tuple.
// It cannot issue qualification, create a guest or grant execution admission.
func CheckKata(ctx context.Context, c config.Config) ([]byte, error) {
	x := c.Execution
	if x == nil || x.Kata == nil || os.Geteuid() == 0 {
		return nil, katalinux.ErrQualification
	}
	base := standardlinux.Settings{ImageRepository: x.ImageRepository, NetworkID: x.NetworkID, BootstrapRoot: x.BootstrapRoot, RunnerUID: os.Geteuid(), PidsLimit: x.PidsLimit}
	profile, err := katalinux.Load(x.Kata.ProfileFile, x.Kata.PublicKeyFile, x.Kata.EvidenceDirectory, c.StateDir, base)
	if err != nil {
		return nil, err
	}
	profile.ObserverSocket = x.Kata.ObserverSocket
	engine, err := dockerengine.OpenReadOnly(c.RuntimeEndpoint, "kata-read-only-preflight", nil)
	if err != nil {
		return nil, err
	}
	defer engine.Close()
	endpoint, err := engine.Probe(ctx)
	if err != nil || endpoint != profile.Manifest.EndpointIdentity {
		return nil, katalinux.ErrQualification
	}
	if err = profile.Probe(ctx, engine); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"profileVersion": profile.ID, "endpointIdentity": endpoint, "expiresAt": profile.Manifest.ExpiresAt, "guest": profile.Manifest.Budget.Guest, "effective": profile.Manifest.Budget.Effective, "tupleMatches": true, "admissionGranted": false})
}
