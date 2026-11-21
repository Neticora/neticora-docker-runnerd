//go:build linux

package onboarding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/journal"
)

type activationPlatform struct {
	*platform
	admitted, lost, mismatch bool
	endpoint                 string
}

func (p *activationPlatform) Config(context.Context, string) ([]byte, error) {
	if p.lost {
		return nil, errors.New("lost response")
	}
	return json.Marshal(protocol.ConfigResponse{AdmissionEnabled: p.admitted, Policy: protocol.LocalPolicy{Generation: "1", AllowedProfiles: []string{"standard-linux-v1"}, AllowedTrustClasses: []protocol.LocalPolicyAllowedTrustClasses{"trusted"}, Limits: protocol.ResourceBudget{CpuMillis: "1000", MemoryBytes: "1000", StorageBytes: "1000", Slots: "1"}}, Protocol: protocol.ProtocolCompatibility{Version: "1.0.0", MinimumAdmissionVersion: "1.0.0", MinimumRecoveryVersion: "1.0.0"}})
}
func (p *activationPlatform) Recovery(context.Context, string, protocol.Outbound) (protocol.RecoveryState, error) {
	endpoint := p.endpoint
	if p.mismatch {
		endpoint = "changed"
	}
	return protocol.RecoveryState{Identity: p.binding.Identity, EndpointIdentity: endpoint}, nil
}

func TestInstalledActivationPreservesIdentityJournalAndExplicitDrain(t *testing.T) {
	for _, fault := range []string{"none", "lost-response", "wrong-endpoint", "missing-qualification", "running-daemon", "changed-tenant"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			o, p := fixture(t)
			if _, e := Setup(ctx, p, o); e != nil {
				t.Fatal(e)
			}
			store, e := journal.OpenRecovery(ctx, o.StateDir, journal.Options{})
			if e != nil {
				t.Fatal(e)
			}
			journalID := store.Health(ctx).JournalID
			store.Close()
			old, _ := os.ReadFile(o.ConfigPath)
			identity, _ := os.ReadFile(o.CredentialPath)
			c, _ := config.Parse(old)
			root := filepath.Dir(o.ConfigPath)
			c.Execution = &config.Execution{Pool: o.PoolID, Enabled: false, Repository: "org/repo", Organization: "org", PolicyFile: filepath.Join(root, "policy"), CapabilitiesFile: filepath.Join(root, "caps"), BootstrapRoot: filepath.Join(root, "bootstrap"), KeysDirectory: filepath.Join(root, "keys"), TrustRoots: filepath.Join(root, "roots"), ImageBundles: filepath.Join(root, "bundles"), ImageRepository: "registry/runner", NetworkID: "customer-network", TrustProvisionedAt: time.Now().UTC().Format(time.RFC3339), PidsLimit: 128, StorageRoot: filepath.Join(filepath.Dir(root), "workspace")}
			remote := &activationPlatform{platform: p, endpoint: "docker-original", lost: fault == "lost-response", mismatch: fault == "wrong-endpoint"}
			if fault == "changed-tenant" {
				c.Connection.TenantID = "another"
			}
			raw, _ := json.Marshal(c)
			prepare := func(context.Context, []byte, time.Time) execution.PreparationReport {
				return execution.PreparationReport{ConfigurationValid: true}
			}
			qualify := func(config.Config, execution.Credentials, time.Time) (protocol.ExecutionSpec, error) {
				if fault == "missing-qualification" {
					return protocol.ExecutionSpec{}, execution.ErrQualification
				}
				return protocol.ExecutionSpec{PolicyGeneration: "1", ProfileVersion: "standard-linux-v1", Resources: protocol.ResourceBudget{CpuMillis: "1000", MemoryBytes: "1000", StorageBytes: "1000", Slots: "1"}}, nil
			}
			if fault == "running-daemon" {
				store, e = journal.OpenRecovery(ctx, o.StateDir, journal.Options{})
				if e != nil {
					t.Fatal(e)
				}
				defer store.Close()
			}
			e = activateExecution(ctx, o.ConfigPath, raw, remote, false, prepare, qualify)
			after, _ := os.ReadFile(o.ConfigPath)
			creds, _ := os.ReadFile(o.CredentialPath)
			if !bytes.Equal(identity, creds) {
				t.Fatal("identity replaced")
			}
			if fault != "none" {
				if e == nil || !bytes.Equal(old, after) {
					t.Fatal("failed activation changed original", e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			installed, e := config.Parse(after)
			if e != nil || !installed.Execution.Enabled {
				t.Fatal("configuration not installed", e)
			}
			if _, e = os.Stat(filepath.Join(o.StateDir, "admission.drained")); e != nil {
				t.Fatal("activation lifted local drain")
			}
			if e = activateExecution(ctx, o.ConfigPath, raw, remote, true, prepare, qualify); e == nil {
				t.Fatal("resume bypassed explicit platform admission")
			}
			remote.admitted = true
			if e = activateExecution(ctx, o.ConfigPath, raw, remote, true, prepare, qualify); e != nil {
				t.Fatal(e)
			}
			if _, e = os.Stat(filepath.Join(o.StateDir, "admission.drained")); !os.IsNotExist(e) {
				t.Fatal("explicit resume retained drain", e)
			}
			store, e = journal.OpenRecovery(ctx, o.StateDir, journal.Options{})
			if e != nil {
				t.Fatal(e)
			}
			defer store.Close()
			if store.Health(ctx).JournalID != journalID {
				t.Fatal("journal replaced")
			}
		})
	}
}
