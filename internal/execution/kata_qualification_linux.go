//go:build linux && runnerd_qualification

package execution

import (
	"bytes"
	"encoding/json"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

// Explicit campaign configuration enters the normal service/controller lifecycle
// only in qualification builds. Neither ordinary builds nor Load accept it.
func openConfiguredQualification(c config.Config, store *journal.SQLiteStore, policy *PolicyFile, drained func() bool) (*Controller, func(), error) {
	x := c.Execution
	if x == nil || x.Kata == nil || x.BrokerSocket == "" || c.SourceFile == "" {
		return nil, nil, ErrReconcile
	}
	raw, err := hostfs.ReadPrivate(x.Kata.QualificationBindingFile, 16384)
	if err != nil {
		return nil, nil, err
	}
	if _, err = protocol.CanonicalizeJSON(raw); err != nil {
		return nil, nil, err
	}
	var b katalinux.LabBinding
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil {
		return nil, nil, ErrReconcile
	}
	return OpenQualification(c, c.SourceFile, store, policy, drained, x.Kata.QualificationAuthorityPin, b)
}

// OpenQualification preserves real controller/journal/runtime/image-verification
// behavior. Only the authority declaring completed Kata acceptance is replaced
// by an independently pinned, expiring, private-address-only lab envelope.
// Normal Open, binaries and artifact loaders never select this constructor.
func OpenQualification(c config.Config, configFile string, store *journal.SQLiteStore, policy *PolicyFile, drained func() bool, pin string, binding katalinux.LabBinding) (*Controller, func(), error) {
	x := c.Execution
	if x == nil || x.Kata == nil || c.ControlPlaneURL != binding.ControlPlaneURL || x.Repository != binding.Repository || x.Pool != binding.PoolID || policy.Get() == nil || policy.Get().Limits().Slots != 1 {
		return nil, nil, ErrReconcile
	}
	if katalinux.ValidateLabFiles(binding, configFile, x.PolicyFile, x.CapabilitiesFile) != nil {
		return nil, nil, ErrReconcile
	}
	credentials, key, err := ReadCredentials(c.CredentialFile)
	clear(key)
	if err != nil || credentials.Identity.HostId != binding.HostID || credentials.TenantID != binding.TenantID || credentials.InstallationID != binding.InstallationID || credentials.BootID != binding.BootID {
		return nil, nil, ErrReconcile
	}
	candidate, close, err := openWithKataLoader(c, store, policy, drained, func(file, public, evidence, state string, base standardlinux.Settings) (*katalinux.Profile, error) {
		return katalinux.LoadQualification(file, public, pin, binding, evidence, state, base)
	})
	if err != nil {
		return nil, nil, err
	}
	approved := policy.Get()
	candidate.Policy = func() *standardlinux.Policy { return approved }
	candidate.Drained = func() bool {
		return drained() || katalinux.ValidateLabFiles(binding, configFile, x.PolicyFile, x.CapabilitiesFile) != nil
	}
	return candidate, close, nil
}
