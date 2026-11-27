//go:build linux && runnerd_qualification

package qualfixture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

// PrepareTrial reuses a campaign's host identity/trust/real native journal. Each
// trial has fresh command/execution/attempt identities and separate durable
// control-plane state. It never resets history or alters a previous issuance.
func PrepareTrial(base Config, trial, bootstrap, expiry, previousState, output string) (Config, error) {
	if _, err := os.Lstat("/etc/neticora-runnerd-lab"); err == nil {
		return Config{}, ErrFixture
	}
	until, err := time.Parse(time.RFC3339Nano, expiry)
	authorized, authErr := time.Parse(time.RFC3339Nano, base.Start.Spec.AuthorizationExpiresAt)
	if err != nil || authErr != nil || !until.After(time.Now().Add(30*time.Second)) || !authorized.After(time.Now().Add(30*time.Second)) || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`).MatchString(trial) || base.Identity.HostId != "runnerd09-lab-"+base.CaseID || !filepath.IsAbs(output) || filepath.Clean(output) != output || hostfs.CheckAncestors(filepath.Dir(output)) != nil {
		return Config{}, fmt.Errorf("%w: trial lifetime, identity or protected output", ErrFixture)
	}
	plain, err := hostfs.ReadPrivate(bootstrap, 131072)
	clear(plain)
	if err != nil {
		return Config{}, err
	}
	if previousState != "" {
		previous, err := hostfs.ReadPrivate(previousState, 4<<20)
		if err != nil {
			return Config{}, err
		}
		var state State
		if json.Unmarshal(previous, &state) != nil || state.Version != "runnerd09-fixture-state-v1" || state.CaseID != base.CaseID || !state.ReservationReleased || state.Sequence == "0" {
			return Config{}, ErrFixture
		}
		base.InitialInventoryGeneration, base.PreviousStateHash = state.InventoryGeneration, digest(previous)
		base.InitialNonces = map[string]int64{}
		for nonce, expiry := range state.Nonces {
			if expiry > time.Now().Unix() {
				base.InitialNonces[nonce] = expiry
			}
		}
	} else if base.InitialInventoryGeneration != "" || base.PreviousStateHash != "" || len(base.InitialNonces) != 0 {
		return Config{}, ErrFixture
	}
	base.Start.CommandId = "start-" + base.CaseID + "-" + trial
	base.Start.Spec.ExecutionId = "execution-" + base.CaseID + "-" + trial
	base.Start.Spec.AttemptId = "attempt-" + base.CaseID + "-" + trial
	spec, err := hashed("ExecutionSpec", base.Start.Spec)
	if err != nil {
		return Config{}, err
	}
	json.Unmarshal(spec, &base.Start.Spec)
	command, err := hashed("HostCommand", base.Start)
	if err != nil {
		return Config{}, err
	}
	json.Unmarshal(command, &base.Start)
	base.Cleanup.CommandId = "cleanup-" + base.CaseID + "-" + trial
	base.Cleanup.ExecutionId = base.Start.Spec.ExecutionId
	cleanup, err := hashed("HostCommand", base.Cleanup)
	if err != nil {
		return Config{}, err
	}
	json.Unmarshal(cleanup, &base.Cleanup)
	base.BootstrapFile, base.BootstrapExpiresAt = bootstrap, until.UTC().Format("2006-01-02T15:04:05.000Z")
	if err = os.Mkdir(output, 0700); err != nil {
		return Config{}, err
	}
	if err = os.Mkdir(filepath.Join(output, "state"), 0700); err != nil {
		return Config{}, err
	}
	if err = privateWrite(output, "fixture.json", jsonBytes(base)); err != nil {
		return Config{}, err
	}
	return base, nil
}
