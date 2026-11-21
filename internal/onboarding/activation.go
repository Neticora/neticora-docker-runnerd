package onboarding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/identity"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

type executionPlatform interface {
	Platform
	Config(context.Context, string) ([]byte, error)
	Recovery(context.Context, string, protocol.Outbound) (protocol.RecoveryState, error)
}

// ActivateExecution is an explicit stopped-service operation. It never enrolls,
// signs acceptance, changes platform admission, starts Docker or resets history.
// Resume revalidates everything before lifting the durable local drain fence.
func ActivateExecution(ctx context.Context, installedPath string, candidate []byte, p executionPlatform, resume bool) error {
	return activateExecution(ctx, installedPath, candidate, p, resume, execution.PrepareExecution, execution.Qualification)
}

// Dependencies are fixed by the shipping entrypoint; internal tests exercise
// persistence/response-loss boundaries without granting synthetic CLI authority.
func activateExecution(ctx context.Context, installedPath string, candidate []byte, p executionPlatform, resume bool, prepare func(context.Context, []byte, time.Time) execution.PreparationReport, qualify func(config.Config, execution.Credentials, time.Time) (protocol.ExecutionSpec, error)) error {
	oldRaw, e := hostfs.ReadPrivate(installedPath, config.MaxConfigBytes)
	if e != nil {
		return e
	}
	defer clear(oldRaw)
	old, e := config.Parse(oldRaw)
	if e != nil {
		return e
	}
	next, e := config.ParsePreparation(candidate)
	if e != nil || !sameInstallation(old, next) {
		return ErrState
	}
	// Existing enabled execution configuration can only be resumed unchanged.
	if old.Execution != nil && old.Execution.Enabled {
		copy := old
		x := *old.Execution
		copy.Execution = &x
		copy.Execution.Enabled = false
		if !reflect.DeepEqual(copy, next) {
			return ErrState
		}
	} else if resume {
		return ErrState
	}
	for _, name := range []string{"journal.db", "recovery.anchor.json"} {
		info, err := os.Lstat(filepath.Join(next.StateDir, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("original journal and anchor required; start connection mode first")
		}
	}
	store, e := journal.OpenRecovery(ctx, next.StateDir, journal.Options{})
	if e != nil {
		return e
	} // Holds the same installation lock as the daemon.
	defer store.Close()
	rows, e := store.Incomplete(ctx, agent.ExecutionCursor{}, 1)
	if e != nil || len(rows) != 0 {
		return errors.New("outstanding work requires original execution recovery")
	}
	if reason := store.Health(ctx).Reason; reason != "ready" && reason != "reconciliation-required" {
		return errors.New("journal recovery blocked; original evidence retained")
	}
	report := prepare(ctx, candidate, time.Now())
	if !report.ConfigurationValid {
		return errors.New("execution preparation failed; original configuration retained")
	}
	credentials, key, e := execution.ReadCredentials(next.CredentialFile)
	if e != nil {
		return e
	}
	defer clear(key)
	if e = store.VerifyActivationScope(ctx, agent.StoreScope{InstallationID: credentials.InstallationID, TenantID: credentials.TenantID, HostID: credentials.Identity.HostId, SessionEpoch: credentials.Identity.SessionEpoch, EndpointIdentity: credentials.EndpointIdentity}); e != nil {
		return e
	}
	spec, e := qualify(next, credentials, time.Now())
	if e != nil {
		return e
	}
	token, e := Authenticate(ctx, p, key, credentials.Identity, credentials.BootID)
	if e != nil {
		return e
	}
	binding, e := p.Installation(ctx, token)
	if e != nil || binding.Identity != credentials.Identity || binding.InstallationID != credentials.InstallationID || binding.TenantID != next.Connection.TenantID || binding.RunnerDeploymentID != next.Connection.RunnerDeploymentID || binding.EnrollmentRequestID != next.Connection.EnrollmentRequestID || binding.PublicKeyFingerprint != next.Connection.PublicKeyFingerprint {
		return ErrState
	}
	raw, e := p.Config(ctx, token)
	if e != nil {
		return e
	}
	remote, e := protocol.DecodeConfigResponse(raw)
	if e != nil || (resume && !remote.AdmissionEnabled) {
		return errors.New("explicit platform execution admission required")
	}
	local := protocol.LocalPolicy{Generation: spec.PolicyGeneration, AllowedProfiles: []string{spec.ProfileVersion}, AllowedTrustClasses: []protocol.LocalPolicyAllowedTrustClasses{"trusted"}, Limits: spec.Resources}
	narrow, e := identity.NarrowPolicy(local, remote.Policy)
	if resume && (e != nil || remote.Policy.Generation != spec.PolicyGeneration || !reflect.DeepEqual(local, narrow)) {
		return errors.New("platform policy does not authorize qualified execution")
	}
	request, e := protocol.EncodeValidated("RecoveryRequest", map[string]any{"entries": []any{}})
	if e != nil {
		return e
	}
	state, e := p.Recovery(ctx, token, request)
	if e != nil || state.Identity != credentials.Identity || state.EndpointIdentity != credentials.EndpointIdentity || len(state.Entries) != 0 {
		return errors.New("platform recovery must confirm original empty execution scope")
	}
	// A second runtime/trust check closes the network-wait observation window.
	if !prepare(ctx, candidate, time.Now()).ConfigurationValid {
		return ErrState
	}
	if _, e = qualify(next, credentials, time.Now()); e != nil {
		return e
	}
	root, e := hostfs.OpenState(next.StateDir)
	if e != nil {
		return e
	}
	defer root.Close()
	drainPath := filepath.Join(next.StateDir, "admission.drained")
	if _, e = os.Lstat(drainPath); os.IsNotExist(e) {
		if e = Create(drainPath, nil); e != nil {
			return e
		}
	} else if _, e = hostfs.ReadPrivate(drainPath, 0); e != nil {
		return e
	}
	if !resume {
		next.Execution.Enabled = true
		active, e := json.Marshal(next)
		if e != nil {
			return e
		}
		if e = replaceConfiguration(installedPath, oldRaw, active); e != nil {
			return e
		}
		return nil
	}
	// Configuration must still be the exact version verified under the lock.
	current, e := hostfs.ReadPrivate(installedPath, config.MaxConfigBytes)
	if e != nil || !bytes.Equal(current, oldRaw) {
		return ErrState
	}
	if e = root.Remove("admission.drained"); e != nil {
		return e
	}
	dir, e := root.Open(".")
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}

func sameInstallation(a, b config.Config) bool {
	return a.Connection != nil && b.Connection != nil && *a.Connection == *b.Connection && a.ControlPlaneURL == b.ControlPlaneURL && a.StateDir == b.StateDir && a.RuntimeEndpoint == b.RuntimeEndpoint && a.CredentialFile == b.CredentialFile && b.Execution != nil && b.Execution.Pool == b.Connection.RunnerDeploymentID
}

func replaceConfiguration(path string, expected, data []byte) error {
	root, e := hostfs.OpenState(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer root.Close()
	n, e := nonce()
	if e != nil {
		return e
	}
	name := ".activation-" + n
	f, e := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer root.Remove(name)
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return ErrState
	}
	current, e := hostfs.ReadPrivate(path, config.MaxConfigBytes)
	if e != nil || !bytes.Equal(current, expected) {
		return ErrState
	}
	if e = root.Rename(name, filepath.Base(path)); e != nil {
		return e
	}
	dir, e := root.Open(".")
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
