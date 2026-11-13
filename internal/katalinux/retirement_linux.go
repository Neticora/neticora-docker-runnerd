//go:build linux

package katalinux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

const retirementVersion = "runnerd09-retirement-v1"

type retirementFenceKey struct{}
type retirementFence struct {
	profile      *Profile
	plan         dockerengine.Plan
	record       RetirementRecord
	runtimeGuard func() error
}

func (p *Profile) retirementRecord(plan dockerengine.Plan) (RetirementRecord, error) {
	var r RetirementRecord
	if !ownedName(plan.Name) {
		return r, ErrQualification
	}
	root, err := hostfs.OpenState(p.EvidenceDirectory)
	if err != nil {
		return r, err
	}
	defer root.Close()
	err = readCheckedBlockJSON(root, plan.Name+".retirement.json", &r)
	if err != nil {
		return r, err
	}
	if r.Version != retirementVersion || r.Policy != RetirementPolicy || r.Profile != p.ID || r.Name != plan.Name || r.SpecHash != plan.Config.Labels[dockerengine.LabelPrefix+"spec"] || r.Generation != plan.Config.Labels[dockerengine.LabelPrefix+"generation"] || !retirementDigest(r.Container) || !retirementDigest(r.OperationID) || r.Cgroup.Name != plan.Name || r.Cgroup.Profile != p.ID || r.Cgroup.Phase != "ready" || r.Cgroup.Device == 0 || r.Cgroup.Inode == 0 {
		return r, ErrQualification
	}
	switch r.Phase {
	case "INTENT":
		if r.FencedAt != "" || r.DisposedAt != "" {
			return r, ErrQualification
		}
	case "FENCED", "RECLAIMING", "RECLAIMED":
		if !retirementTime(r.FencedAt) || r.DisposedAt != "" {
			return r, ErrQualification
		}
	case "DISPOSED":
		if !retirementTime(r.FencedAt) || !retirementTime(r.DisposedAt) || r.Quarantined {
			return r, ErrQualification
		}
	default:
		return r, ErrQualification
	}
	return r, nil
}
func retirementTime(v string) bool { _, err := time.Parse(time.RFC3339Nano, v); return err == nil }
func retirementDigest(v string) bool {
	b, err := hex.DecodeString(v)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == v
}
func (p *Profile) persistRetirement(r RetirementRecord) error {
	root, err := hostfs.OpenState(p.EvidenceDirectory)
	if err != nil {
		return err
	}
	defer root.Close()
	return writeCheckedBlockJSON(root, r.Name+".retirement.json", r)
}

// RequireAcquisition is called before any broker path can grant the runtime a
// resource. The lifecycle flock and broker mutex serialize it against retirement.
// Historical profiles remain readable for cleanup; they cannot launch fresh work.
func (p *Profile) RequireAcquisition(plan dockerengine.Plan) error {
	if !p.brokerOwned || p.Manifest.RetirementPolicy != RetirementPolicy || p.Manifest.Version != MultiBlockVersion || p.Manifest.HostCgroup == nil || !ownedName(plan.Name) {
		return ErrQualification
	}
	for _, path := range []string{p.EvidenceDirectory, p.Manifest.Storage.Runtime.Root} {
		protected, err := hostfs.OpenState(path)
		if err != nil {
			return ErrQualification
		}
		protected.Close()
	}
	_, err := p.retirementRecord(plan)
	if !errors.Is(err, os.ErrNotExist) {
		return ErrQualification
	}
	return nil
}

// BeginRetirement runs only after the broker has durably consumed the exact
// original RemoveExecution grant. No IPC path can supply an owner or worker list.
// The trusted runtime may finish its original removal; the broker cannot launch,
// capture replacement ownership or reclaim residue across this tombstone.
func (p *Profile) BeginRetirement(id string, plan dockerengine.Plan, operationID string) error {
	if p.Manifest.RetirementPolicy == "" {
		return nil
	} // immutable historical cleanup
	if !p.brokerOwned || p.Manifest.RetirementPolicy != RetirementPolicy || !retirementDigest(operationID) {
		return ErrQualification
	}
	existing, err := p.retirementRecord(plan)
	if err == nil {
		if existing.Container != id || existing.OperationID != operationID {
			return ErrQualification
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := hostfs.ReadPrivate(filepath.Join(p.EvidenceDirectory, plan.Name+".json"), 32768)
	var original Evidence
	if err != nil || readEvidence(raw, &original) != nil || original.Version != "runnerd09-physical-v1" || original.Profile != p.ID || original.Container != id || original.SpecHash != plan.Config.Labels[dockerengine.LabelPrefix+"spec"] || original.Generation != plan.Config.Labels[dockerengine.LabelPrefix+"generation"] || original.Absence != nil || original.Cgroup == nil {
		return ErrQualification
	}
	group, err := p.cgroupRecord(plan)
	boot, be := currentCgroupBoot()
	if err != nil || be != nil || boot != group.BootID || group.Phase != "ready" || !sameHostCgroup(original.Cgroup, &group) {
		return ErrQualification
	}
	return p.persistRetirement(RetirementRecord{Version: retirementVersion, Policy: RetirementPolicy, Profile: p.ID, Name: plan.Name, Container: id, SpecHash: original.SpecHash, Generation: original.Generation, OperationID: operationID, Cgroup: group, Sandboxes: original.Sandboxes, Processes: original.Processes, Phase: "INTENT"})
}

// verify requires a positive kernel barrier, not a cached negative procfs scan.
// Trusted host administration/systemd/Docker are outside the adversarial domain.
// No in-scope caller can thaw/delegate/migrate tasks into this root-owned slice.
func (f *retirementFence) verify(ctx context.Context) error {
	p, r := f.profile, f.record
	current, err := p.retirementRecord(f.plan)
	if err != nil || current.Container != r.Container || current.OperationID != r.OperationID || !sameHostCgroup(&current.Cgroup, &r.Cgroup) || !reflect.DeepEqual(current.Sandboxes, r.Sandboxes) || (current.Phase != "FENCED" && current.Phase != "RECLAIMING") {
		return ErrQualification
	}
	boot, err := currentCgroupBoot()
	group, ge := p.cgroupRecord(f.plan)
	if err != nil || ge != nil || boot != r.Cgroup.BootID || !sameHostCgroup(&group, &r.Cgroup) {
		return ErrQualification
	}
	if group.Phase != "ready" {
		return ErrQualification
	}
	return p.observeEmptyFrozen(ctx, f.plan, r.Cgroup)
}
func (p *Profile) retiredPhysicalAbsence(ctx context.Context, id string, plan dockerengine.Plan, group CgroupRecord) error {
	if p.checkReleasedHostCgroup(ctx, plan, &group) != nil {
		return ErrQualification
	}
	for _, root := range p.Manifest.SandboxRoots {
		if _, err := os.Lstat(filepath.Join(root, id)); !errors.Is(err, os.ErrNotExist) {
			return ErrQualification
		}
	}
	block, err := p.blockRecord(plan)
	if err != nil || p.blockReleased(plan, block) != nil {
		return ErrQualification
	}
	return nil
}

// ReclaimRetired never authorizes Docker operations or creates a missing record.
// Unknown/surviving workers leave a frozen, owned quarantine. Their descriptors,
// mappings and private namespaces cannot authorize a successful disposal.
func (p *Profile) ReclaimRetired(ctx context.Context, id string, plan dockerengine.Plan, operationID string, guard func() error) (err error) {
	if guard == nil {
		return ErrQualification
	}
	r, err := p.retirementRecord(plan)
	if err != nil || r.Container != id || r.OperationID != operationID {
		return ErrQualification
	}
	if r.Phase == "DISPOSED" {
		return p.CheckRetirement(ctx, id, plan)
	}
	raw, e := hostfs.ReadPrivate(filepath.Join(p.EvidenceDirectory, plan.Name+".json"), 32768)
	var original Evidence
	if e != nil || readEvidence(raw, &original) != nil || original.Container != r.Container || original.Profile != r.Profile || original.SpecHash != r.SpecHash || original.Generation != r.Generation || !sameHostCgroup(original.Cgroup, &r.Cgroup) || !reflect.DeepEqual(original.Sandboxes, r.Sandboxes) || !reflect.DeepEqual(original.Processes, r.Processes) {
		return ErrQualification
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, p.quarantineRetirement(plan, id, operationID))
		}
	}()
	if err = guard(); err != nil {
		return err
	}
	if r.Phase == "RECLAIMED" {
		if err = p.finishRetired(ctx, id, plan, guard); err != nil {
			return err
		}
		return p.completeRetirement(ctx, id, plan, operationID, guard)
	}
	f := &retirementFence{profile: p, plan: plan, record: r, runtimeGuard: guard}
	r, err = p.FenceRetirement(ctx, id, plan, operationID, guard)
	if err != nil {
		return err
	}
	f.record = r
	if err = f.verify(ctx); err != nil {
		return err
	}
	if r.Phase == "FENCED" {
		r.Phase = "RECLAIMING"
		r.Quarantined = false
		if err = p.persistRetirement(r); err != nil {
			return err
		}
	}
	f.record = r
	ctx = context.WithValue(ctx, retirementFenceKey{}, f)
	combined := func() error {
		if e := guard(); e != nil {
			return e
		}
		return f.verify(ctx)
	}
	if err = p.VerifyAbsent(ctx, id, plan, combined); err != nil {
		return err
	}
	if err = guard(); err != nil {
		return err
	}
	if err = p.BrokerAbsence(ctx, id, plan); err != nil {
		return err
	}
	return p.completeRetirement(ctx, id, plan, operationID, guard)
}

func (p *Profile) observeEmptyFrozen(ctx context.Context, plan dockerengine.Plan, expected CgroupRecord) error {
	protected, err := hostfs.OpenState(p.Manifest.Storage.Runtime.Root)
	if err != nil {
		return ErrQualification
	}
	protected.Close()
	// Reuse the exact same verifier without weakening durable-state validation:
	// inspect the live barrier here, and recheck through verify after persistence.
	groupValue, err := p.cgroupRecord(plan)
	group := &groupValue
	boot, be := currentCgroupBoot()
	if err != nil || be != nil || group.Phase != "ready" || group.BootID != boot || !sameHostCgroup(group, &expected) {
		return ErrQualification
	}
	_, populated, err := inspectCgroup(*group)
	if err != nil || populated {
		return ErrQualification
	}
	root, err := os.OpenRoot(hostCgroupRoot + group.Path)
	if err != nil {
		return ErrQualification
	}
	defer root.Close()
	freeze, err := root.ReadFile("cgroup.freeze")
	events, e := root.ReadFile("cgroup.events")
	if err != nil || e != nil || strings.TrimSpace(string(freeze)) != "1" || len(events) > 4096 {
		return ErrQualification
	}
	frozen := false
	for _, line := range strings.Split(strings.TrimSpace(string(events)), "\n") {
		v := strings.Fields(line)
		if len(v) == 2 && v[0] == "frozen" {
			if frozen || v[1] != "1" {
				return ErrQualification
			}
			frozen = true
		}
	}
	if !frozen {
		return ErrQualification
	}
	return nil
}
func (p *Profile) CheckRetirement(ctx context.Context, id string, plan dockerengine.Plan) error {
	r, err := p.retirementRecord(plan)
	if err != nil || r.Container != id || r.Phase != "DISPOSED" || r.Quarantined {
		return ErrQualification
	}
	boot, be := currentCgroupBoot()
	if be != nil || boot != r.Cgroup.BootID {
		return ErrQualification
	}
	if err = p.priorProcessesAbsent(r.Processes); err != nil {
		return err
	}
	return p.retiredPhysicalAbsence(ctx, id, plan, r.CgroupWithPhase("released"))
}
func (r RetirementRecord) CgroupWithPhase(phase string) CgroupRecord {
	g := r.Cgroup
	g.Phase = phase
	return g
}
func (p *Profile) RetirementEvidence(ctx context.Context, id string, plan dockerengine.Plan) (*RetirementProof, error) {
	if p.Manifest.RetirementPolicy == "" {
		return nil, nil
	}
	if err := p.CheckRetirement(ctx, id, plan); err != nil {
		return nil, err
	}
	r, err := p.retirementRecord(plan)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	raw, err = protocol.CanonicalizeJSON(raw)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(raw)
	return &RetirementProof{Version: retirementVersion, Policy: r.Policy, RecordHash: hex.EncodeToString(hash[:]), OperationID: r.OperationID}, nil
}

// FenceRetirement can only advance an existing original retirement. It cannot
// create resources, issue authority, signal unknown workers or reclaim storage.
func (p *Profile) FenceRetirement(ctx context.Context, id string, plan dockerengine.Plan, operationID string, guard func() error) (r RetirementRecord, err error) {
	if guard == nil {
		return r, ErrQualification
	}
	r, err = p.retirementRecord(plan)
	if err != nil || r.Container != id || r.OperationID != operationID {
		return r, ErrQualification
	}
	if r.Phase == "DISPOSED" {
		return r, ErrQualification
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, p.quarantineRetirement(plan, id, operationID))
		}
	}()
	if err = guard(); err != nil {
		return r, err
	}
	if r.Phase == "INTENT" {
		// Verify identity BEFORE freezing. No signal or stop is sent to uncertain
		// workers. Kernel populated includes all descendant processes and threads.
		group, e := p.verifyHostCgroup(ctx, plan, nil)
		if e != nil || !sameHostCgroup(group, &r.Cgroup) {
			return r, ErrQualification
		}
		if _, err = p.cgroupCommand(ctx, p.Manifest.HostCgroup.SystemctlBinary, "--no-pager", "--no-ask-password", "freeze", "--", group.Unit); err != nil {
			return r, ErrQualification
		}
		// Persist the barrier only after the full positive observation. A failed
		// observation leaves INTENT/quarantine, not a fabricated successful fence.
		candidate := r
		candidate.Phase = "FENCED"
		candidate.FencedAt = time.Now().UTC().Format(time.RFC3339Nano)
		// Use a direct check while INTENT remains durable; the public verifier
		// requires a durable FENCED state, so validate kernel via a scoped helper.
		if err = p.observeEmptyFrozen(ctx, plan, r.Cgroup); err != nil {
			return r, err
		}
		r = candidate
		r.Quarantined = false
		if err = p.persistRetirement(r); err != nil {
			return r, err
		}
	}
	f := &retirementFence{profile: p, plan: plan, record: r}
	if err = f.verify(ctx); err != nil {
		return r, err
	}
	return r, nil
}

func (p *Profile) quarantineRetirement(plan dockerengine.Plan, id, op string) error {
	r, err := p.retirementRecord(plan)
	if err != nil {
		return err
	}
	if r.Container != id || r.OperationID != op || r.Phase == "DISPOSED" {
		return ErrQualification
	}
	r.Quarantined = true
	return p.persistRetirement(r)
}
func (f *retirementFence) reclaim(ctx context.Context) error {
	r, err := f.profile.retirementRecord(f.plan)
	if err != nil || r.Phase != "RECLAIMING" {
		return ErrQualification
	}
	return f.verify(ctx)
}

// seal removes acquisition authority before the kernel barrier can be thawed.
// After RECLAIMED no path may unlink metadata or release a new block allocation.
func (f *retirementFence) seal(ctx context.Context) error {
	if err := f.reclaim(ctx); err != nil {
		return err
	}
	p := f.profile
	r, err := p.retirementRecord(f.plan)
	if err != nil {
		return err
	}
	if err = p.retiredStorageAbsent(r.Container, f.plan); err != nil {
		return err
	}
	r.Phase = "RECLAIMED"
	r.Quarantined = false
	return p.persistRetirement(r)
}
func (p *Profile) retiredStorageAbsent(id string, plan dockerengine.Plan) error {
	for _, root := range p.Manifest.SandboxRoots {
		if _, err := os.Lstat(filepath.Join(root, id)); !errors.Is(err, os.ErrNotExist) {
			return ErrQualification
		}
	}
	block, err := p.blockRecord(plan)
	if err != nil || p.blockReleased(plan, block) != nil {
		return ErrQualification
	}
	return nil
}

// finishRetired is read-only with respect to metadata and block storage. Only the
// positively empty original systemd unit may be thawed/stopped. This is also the
// sole retry path after a crash removes the kernel fence.
func (p *Profile) finishRetired(ctx context.Context, id string, plan dockerengine.Plan, guard func() error) error {
	r, err := p.retirementRecord(plan)
	if err != nil || r.Container != id || r.Phase != "RECLAIMED" {
		return ErrQualification
	}
	if err = guard(); err != nil {
		return err
	}
	if err = p.priorProcessesAbsent(r.Processes); err != nil {
		return err
	}
	if err = p.retiredStorageAbsent(id, plan); err != nil {
		return err
	}
	raw, err := hostfs.ReadPrivate(filepath.Join(p.EvidenceDirectory, plan.Name+".json"), 32768)
	var original Evidence
	if err != nil || readEvidence(raw, &original) != nil || original.Profile != r.Profile || original.Container != id || original.SpecHash != r.SpecHash || original.Generation != r.Generation || !sameHostCgroup(original.Cgroup, &r.Cgroup) || !reflect.DeepEqual(original.Sandboxes, r.Sandboxes) || !reflect.DeepEqual(original.Processes, r.Processes) {
		return ErrQualification
	}
	current, ce := p.cgroupRecord(plan)
	if ce != nil || !sameHostCgroup(&current, &r.Cgroup) {
		return ErrQualification
	}
	group, err := p.releaseHostCgroup(ctx, plan)
	if err != nil {
		return err
	}
	if err = guard(); err != nil {
		return err
	}
	if group == nil || !sameHostCgroup(group, &r.Cgroup) {
		return ErrQualification
	}
	if err = p.retiredPhysicalAbsence(ctx, id, plan, *group); err != nil {
		return err
	}
	block, err := p.blockRecord(plan)
	if err != nil {
		return err
	}
	original.Cgroup = group
	original.Block = &block
	original.Absence = &PhysicalAbsence{CgroupRemoved: true, DeviceDetached: true, MountsRemoved: true, ContainerAbsent: true, SandboxAbsent: true, VMAbsent: true, NetworkRemoved: true, StorageRemoved: true, VerifiedAt: time.Now().UTC().Format(time.RFC3339Nano), ObservationSource: "qualified-host-procfs-runtime-state-v1"}
	root, err := hostfs.OpenState(p.EvidenceDirectory)
	if err != nil {
		return err
	}
	defer root.Close()
	return persist(root, plan.Name+".json", original)
}
func (p *Profile) completeRetirement(ctx context.Context, id string, plan dockerengine.Plan, op string, guard func() error) error {
	r, err := p.retirementRecord(plan)
	if err != nil || r.Phase != "RECLAIMED" || r.Container != id || r.OperationID != op {
		return ErrQualification
	}
	if err = guard(); err != nil {
		return err
	}
	if err = p.BrokerAbsence(ctx, id, plan); err != nil {
		return err
	}
	r.Phase = "DISPOSED"
	r.Quarantined = false
	r.DisposedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return p.persistRetirement(r)
}
