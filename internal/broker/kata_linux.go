//go:build linux

package broker

import (
	"context"
	"encoding/json"
	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	"os"
	"time"
)

type KataConfig struct {
	ProfileFile       string `json:"profileFile"`
	PublicKeyFile     string `json:"publicKeyFile"`
	EvidenceDirectory string `json:"evidenceDirectory"`
	JournalDirectory  string `json:"journalDirectory"`
	QualificationPin  string `json:"qualificationPin,omitempty"`
	NetworkGuardFile  string `json:"networkGuardFile,omitempty"`
}
type protectedKata struct {
	profile      *katalinux.Profile
	engine       *dockerengine.Engine
	networkGuard func(context.Context) error
}

func (k *protectedKata) Plan(scope agent.StoreScope, s protocol.ExecutionSpec) (dockerengine.Plan, error) {
	p, err := k.profile.RecoveryPlan(scope, s)
	p.RecoveryOnly = false // Original plan identity; launch checks remain separate.
	return p, err
}
func (k *protectedKata) Admit(ctx context.Context, scope agent.StoreScope, s protocol.ExecutionSpec, policy *standardlinux.Policy, now time.Time) error {
	plan, err := k.Plan(scope, s)
	if err != nil || k.profile.RequireAcquisition(plan) != nil {
		return ErrRejected
	}
	if err := k.profile.Admit(scope, s, policy, now); err != nil {
		return err
	}
	if k.networkGuard != nil {
		if err := k.networkGuard(ctx); err != nil {
			return err
		}
	}
	return k.profile.Probe(ctx, k.engine)
}
func (k *protectedKata) Prepare(ctx context.Context, p dockerengine.Plan) error {
	if err := k.profile.PrepareHealth(p); err != nil {
		return err
	}
	return k.profile.Prepare(p)
}
func (k *protectedKata) Prepared(id string, p dockerengine.Plan) error {
	return k.profile.CapturePrepared(id, p)
}
func (k *protectedKata) VerifyStorage(ctx context.Context, p dockerengine.Plan) error {
	return k.profile.VerifyStorage(ctx, p)
}
func (k *protectedKata) Capture(ctx context.Context, id string, p dockerengine.Plan) error {
	return k.profile.Capture(ctx, id, p)
}
func (k *protectedKata) Healthy(p dockerengine.Plan, start string, now time.Time) bool {
	return k.profile.Healthy(p, start, now)
}
func (k *protectedKata) BeginRetirement(id string, p dockerengine.Plan, operationID string) error {
	return k.profile.BeginRetirement(id, p, operationID)
}
func (k *protectedKata) Dispose(ctx context.Context, id string, p dockerengine.Plan, operationID string, guard func() error) error {
	cleanup := func() error { return k.profile.VerifyAbsent(ctx, id, p, guard) }
	if k.profile.Manifest.RetirementPolicy != "" {
		cleanup = func() error { return k.profile.ReclaimRetired(ctx, id, p, operationID, guard) }
	}
	if err := cleanup(); err != nil {
		return err
	}
	k.profile.CleanHealth(p)
	if _, err := os.Lstat(k.profile.HealthRoot() + "/" + p.Name); !os.IsNotExist(err) {
		return ErrQuarantined
	}
	return nil
}
func (k *protectedKata) Absence(ctx context.Context, id string, p dockerengine.Plan) error {
	if _, err := os.Lstat(k.profile.HealthRoot() + "/" + p.Name); !os.IsNotExist(err) {
		return ErrQuarantined
	}
	if k.profile.Manifest.RetirementPolicy != "" {
		if err := k.profile.CheckRetirement(ctx, id, p); err != nil {
			return err
		}
	}
	return k.profile.BrokerAbsence(ctx, id, p)
}
func (k *protectedKata) Evidence(ctx context.Context, id string, p dockerengine.Plan) (json.RawMessage, error) {
	if err := k.Absence(ctx, id, p); err != nil {
		return nil, err
	}
	record, err := k.profile.PhysicalEvidence(ctx, id, p)
	if err != nil {
		return nil, err
	}
	return json.Marshal(record)
}

func (k *protectedKata) Check(ctx context.Context) (string, error) {
	if err := k.profile.Probe(ctx, k.engine); err != nil {
		return "", err
	}
	return k.profile.ID, nil
}

func (k *protectedKata) Origin() (json.RawMessage, error) { return k.profile.BrokerOrigin() }
func (k *protectedKata) Observe(ctx context.Context, id string, p dockerengine.Plan) error {
	if k.profile.Manifest.RetirementPolicy != "" {
		return ErrQuarantined
	}
	return k.profile.ObserveBrokerRecovery(ctx, id, p)
}
func (k *protectedKata) RecoverDispose(ctx context.Context, id string, p dockerengine.Plan, guard func() error) error {
	if k.profile.Manifest.RetirementPolicy != "" {
		return ErrQuarantined
	}
	return k.profile.BrokerRecoverDispose(ctx, id, p, guard)
}

func (k *protectedKata) Retirement(ctx context.Context, id string, p dockerengine.Plan) (*katalinux.RetirementProof, error) {
	return k.profile.RetirementEvidence(ctx, id, p)
}
