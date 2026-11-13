# Runnerd09 configuration and qualification harness

The ordinary daemon accepts only independently qualified production profiles.
It must not receive invented acceptance references to bootstrap its own tests.
`runnerd-qualification` is a separate Linux amd64 binary built with
`runnerd_qualification`. Its distinct Ed25519 lab envelope requires
`qualified:false`, empty acceptance, a separate pinned lab authority, a private
HTTPS control-plane address and exact VM/boot/tenant/host/pool/config bindings.
Ordinary builds and `katalinux.Load` reject this envelope. An explicit campaign
configuration in a qualification build can select the same bounded loader from
the actual daemon's normal service entrypoint. No lab result declares completed
production acceptance.

## Enrolled product campaigns

The project owner may authorize an exact isolated campaign to collect genuine
acceptance evidence. No external approval authority is required. The signed lab
envelope retains `qualified:false` and empty acceptance; it may bind real tenant,
host and pool UUIDs with the original `enrollment:UUID` installation. The existing
private HTTPS, current boot/DMI/UID, six-hour expiry and immutable configuration
bindings still apply. Never invent acceptance references to bootstrap tests.

Build the actual `cmd/runnerd` executable with `runnerd_qualification`. With an
existing broker socket, set `execution.kata.qualificationBindingFile` and
`execution.kata.qualificationAuthorityPin`. The normal service uses the existing
controller, native journal and broker transport; no test controller replaces it.
The binding must match the exact daemon/policy/capability files and original
enrollment identity. Configuration drift drains the campaign. Ordinary builds
reject this configuration, and production profile verification remains strict.

The isolated platform instance separately pins the exact owner-signed host
artifact hash. Removing that pin blocks new admission while immutable historical
admission retains its original cleanup and final-ACK authority. Broker execution
grants, transactional commitment, resource ownership and disposal verification
remain unchanged. Keep production dispatch disabled and record each acceptance
case only after its own genuine requirements pass.

An enrolled campaign may authorize up to two concurrent slots, bounded by the
signed Kata block pool's concurrent-allocation limit and the existing local and
platform capacity checks. Per-execution resource budgets remain unchanged.

`runnerctl resume` explicitly clears only the durable local administrative drain.
It requires the service owner/root, a live ready controller, healthy reconciled
journal, no unfinished executions, original Docker peer continuity and current
campaign files/expiry. It never changes enrollment, session, boot, resource
ownership or historical records. Startup preserves a prior drain. Missing runtime
authority, used-host peer transitions and unresolved cleanup require their own
recovery procedures. Platform admission and committed broker grants remain
separate requirements. Network qualification requirements are documented in
[NETWORK-ISOLATION.md](NETWORK-ISOLATION.md).

### Enrollment without controller Docker authority

The unprivileged service first enrolls using the normal protected token/state
flow. A trusted root operator then uses `runnerd-enroll --observe-runtime` with
explicit `--runtime-endpoint`, `--runtime-observation`, `--installation-id`,
`--tenant-id` and `--host-id`. This reads the actual peer and writes an exclusive,
fsynced observation bound to that original installation/tenant/host/current boot.
The output requires root-owned, non-writable directory ancestry. Its public
metadata is readable by the service; it contains no credentials or launch grant.

Export credentials as the same service UID using the original enrollment state,
`--installation-id` and `--runtime-observation`, without `--runtime-endpoint`.
The reader requires root ownership, no writable alias/ancestor, a single regular
file, exact scope and an observation no older than five minutes. It never opens
Docker or falls back to another peer source. The original enrolled seed/key and
server receipt are preserved. After verifying durable export, use the existing
`--retire-attempt` operation to retire the obsolete token/seed attempt while
retaining identity and receipt. Never reenroll or reset state to recover a failure.

Before first admission only, a Docker restart can invalidate the exported peer.
`runnerd-enroll --refresh-unused-runtime` consumes a fresh root observation and
an independently platform-signed initial-binding certificate. It requires the
original empty native journal, original enrollment receipt/key/session/boot,
explicit issuer public key and authenticated HTTPS endpoint. Durable original
credentials, request nonce and certificate precede atomic credential replacement.
The isolated platform must explicitly allow that exact host and reject all prior
heartbeat, inventory, qualification, execution, command, event, reservation,
operation or peer-recovery history. One audited request pins one target peer;
replay never selects a different peer or grants execution authority. Used hosts
remain on the existing recovery path. Never restart Docker between this initial
binding and campaign execution without supported recovery.

## Build and preserve provenance

From this repository, use a fresh output beneath a protected directory on the
operator workstation. `/tmp` may be tmpfs: keep durable evidence on an actual
local persistent filesystem. All ancestors must be root/operator owned and must
not be group/other writable, except root-owned sticky temporary directories.

```sh
umask 077
campaign=$(mktemp -d /var/tmp/runnerd09.XXXXXXXX)
bash packaging/build-qualification.sh "$campaign/build"
TMPDIR=/var/tmp go test -race ./...
TMPDIR=/var/tmp go test -race -tags runnerd_qualification \
  -skip '^TestBuiltCandidateQualification$' ./...
```

The excluded test is the existing signed-release/SBOM qualification, which needs
its own built-release inputs and verifier; this is not a release qualification.
The build receipt records the source commit, dirty state, Go version, source
file hashes and exact binary hashes. Preserve candidate snapshots and failures.
The normal release builder does not set the qualification tag and cannot include
the lab CLI. Run the separate release process before publishing any artifact.

## Inputs and authority separation

Use the paired tuple example in `neticora-k8s/infra/runnerd/kata/`. Replace every
placeholder using reviewed host inventory. Do not guess installation IDs,
network IDs, disk IDs or endpoints. The dedicated VM needs the existing lab
marker, explicit Docker/Kata setup, protected service account, bounded ext4
pool/runtime volumes, dedicated Docker storage and customer-owned bridge.
This harness does not install runtimes, mount disks or change network policy.

| Role | Required material | Authority |
| --- | --- | --- |
| Workstation | inspected tuple, VM public identity, protected per-attempt JIT/bootstrap, expiry | TLS fixture key, ephemeral lab signer, image signer stay here |
| Controller | paired daemon config, policy, capabilities, signed lab profile, public lab key, CA, signed image root/bundle | UID must be non-root; identity key generated locally on VM |
| Observer | matching root-owned config/profile/public key/binding | root only; exact network/journal/evidence/bootstrap tuple; no provider key |
| Production | independently reviewed host qualification, Kata acceptance, image trust and operator-approved execution configs | ordinary validation/signing flow; never replaced with lab artifacts |

`runnerd-config --input /private/bundle.json --output /private/fresh-output`
renders matching daemon/observer configuration and a hash/ownership receipt.
It does not install, validate unavailable qualification, start services or grant
admission. The receipt lists still-required files. An enabled execution config
must have separate credentials/journal/trust/handoff paths and consistent role
socket, UID, runtime endpoint, journal, evidence, bootstrap, network and PID limit.

## Provision a campaign

1. Review the example tuple request and stage it root-owned 0600 beneath a
   root-owned 0700 VM staging directory. Stage the candidate root-owned 0555 at
   `/opt/neticora-runnerd09-qualification/CASE/runnerd-qualification`; independently
   compare its SHA256 with workstation provenance. Never execute root binaries
   beneath a service/user-writable directory.
2. Run `--role inspect --config /root-private/tuple.json` as root on the VM.
   Inspection reads actual Docker identity/version/overlay2, pinned binaries and
   configs, kernel/boot/DMI, ext4 UUIDs/device numbers/capacity and actual runtime
   registration. It creates no guest and does not assert qualification.
3. Create `/var/lib/neticora-runnerd09-lab/config/CASE/client` service-owned 0700
   under root-owned 0710 parents with the service group. Run
   `--role identity --case CASE --endpoint OBSERVED_DOCKER_ID --output
   /var/lib/neticora-runnerd09-lab/config/CASE/client/identity.json` as that service
   account. Identity generation is exclusive and durable; it never uses the real
   enrolled host key. Copy **public metadata only** to the workstation.
4. Combine the inspected plan with `hostIdentity`, `hostPublicKey`,
   `bootstrapFile` (workstation-only protected path) and actual
   `bootstrapExpiresAt`. Run `--role prepare --config /private/prepare.json
   --output /private/fresh-plan` on the workstation. This creates expiring lab
   profiles, real image signatures, paired configs and a manifest with thirteen
   role files. `review-bundle` contains reviewable configuration; inspect it
   before installing. This is a concrete review artifact, not independent human
   approval. Candidate capability/seccomp/device/security review remains required.
5. Copy **only** `manifest.json`, `review-bundle-input.json` and the manifest's
   thirteen `roleFiles` to root-private VM staging. Never transfer `operator/`,
   TLS/signing private keys, original App credentials or plaintext JIT. Install
   the reviewed helper scripts root-owned. Independently record manifest,
   candidate and helper hashes and the lab public DER pin.
6. Run `provision-runnerd09-lab.py` with `--source`, `--manifest-sha256`,
   `--authority-pin`, `--binary`, `--binary-sha256` and `--check-only` first.
   Then run the identical command without `--check-only`. It validates all role
   hashes and destinations, signed envelope, existing VM public key/boot and
   private ownership. Writes use exclusive files and anchored directory
   descriptors. Existing files, symlinks, copied operator material, production
   credential paths and different ownership are refused. Partial output is
   retained for review; no overwrite/automatic rollback is attempted.

After installation, repeat the pinned installer invocation with
`--verify-installed`. This reads installed files through anchored no-symlink
descriptors, checks exact bytes/UID/0600 ownership against the role manifest,
and rechecks VM public identity, boot and DMI. It never rewrites artifacts or
starts services. This is the post-install verification step before a trial.

The installer prepares `/run/neticora-runnerd09-qualification/CASE/` and separate
client/root trust paths. It never changes the existing pool owner/index, journal,
real enrolled identity, production units, GitOps configuration or admission.

Expired lab grants require a fresh plan, not timestamp edits. The tagged
`--role audit-journal --config /private/controller-config.json` takes the native
exclusive journal lock as the service UID and refuses unresolved/unacknowledged
executions, wrong identity/session or a missing database. The infra helper
`renew-runnerd09-lab.py` additionally checks old/new manifest and authority pins,
stopped roles, an empty allocation/container/VM inventory and unchanged VM/boot/
scope/runtime/storage. Use its `--check-only` first. It archives old role artifacts
before anchored atomic replacement, retains the existing identity and journal,
and leaves services stopped. Partial renewal requires explicit reconciliation.

## Run repeatable trials

Use `--role prepare-trial --config /private/plan/operator/fixture.json --trial
TRIAL --bootstrap-file /private/fresh-bootstrap.json --bootstrap-expires-at
ACTUAL_EXPIRY --output /private/fresh-trial`. Trials keep the same campaign
identity/profile/native journal and use fresh execution/attempt/command IDs.
Do not reuse trial IDs. Run one trial at a time; start the next only after the
previous reservation, final ACK and physical cleanup are verified. The original
prepared config is immutable; an expired issuance is never silently extended.

For the first trial of a genuinely fresh journal, omit `--previous-state`.
For subsequent trials, pass the prior closed fixture's `state.json` using
`--previous-state`. Provisioning refuses unresolved prior reservations and seeds
the next fixture's monotonic inventory generation from that protected state,
recording its hash. Never reset an existing journal to start another campaign.

`qualify-runnerd09.py --help` lists coordinator arguments. Supply protected plan,
trial, candidate and SSH paths, independently pinned candidate/helper hashes,
the lab authority pin, exact phase/mode, fresh durable off-VM output and timeout.
The remote helper and its sibling installer must be root-staged together. The
coordinator starts the TLS fixture on the private bridge and runs the VM roles in
explicit constrained transient systemd units. Units are never enabled and have
`Restart=no`. Observer gets only its storage/evidence/runtime write paths and
reviewed device/capability permissions; controller runs without capabilities,
with its exact Docker socket group and private journal/key/handoff write paths.

The controller remains trusted host software: access to this rootful Docker
socket is root-equivalent despite its non-root UID and empty capability set.
Root-observer peer authentication separates authorized callers and protocols;
it does not contain a compromised Docker-authorized controller. Kata guest
isolation does not imply controller containment. A deployment requiring that
additional boundary needs independently trusted Docker authorization, including
payload and resource-ownership enforcement, and separate qualification. A
method/path-only proxy or dedicated rootful daemon cannot establish it.

Production cgroup preparation polls the one durably recorded systemd slice for
up to five seconds after queued creation. It never recreates the slice while
waiting; mismatched ownership, limits or unexpected state fail closed. Restart
trials wait for the killed unit's PID to exit and its collected unit to disappear
before starting the same unit again. A replacement PID or bounded-wait expiry
fails the trial without resetting systemd state.

Supported experiments:

| Mode | Phases | Required evidence |
| --- | --- | --- |
| `observe` | `none` | real native execution, final ACK, root-observer physical proof, fixture release |
| `restart` | `before-command-ack`, `after-command-ack`, `after-runtime-exit`, `before-native-event-ack`, `before-runtime-remove` | live waiting barrier saved/fsynced off VM, exact transient controller SIGKILL, same-journal restart, complete proof |
| `restart` | `journal:METHOD:STAGE` | same, at actual SQLite commit/anchor boundary |
| `response-loss` | `command-reply-loss`, `issuance-reply-loss`, `create-reply-loss`, `start-reply-loss`, `event-reply-loss`, `remove-verification-loss` | durable fault hit, same-attempt replay, final proof; no invented process crash |
| `power-loss-fence` | `journal:AcceptCommand:before-commit` only | verified idle allocation index, no owned containers/QEMU/shim, explicit disposable domain + DMI UUID + reviewed domain XML hash, off-VM barrier, real `virsh destroy/start`, changed boot, refusal to reopen stale authority |

Journal methods: `AcceptCommand`, `PutStartIntent`, `RecordObservation`,
`RequireCleanup`, `CompleteCleanup`, `AckEvents`. Stages: `before-commit`,
`after-commit`, `after-anchor`. Fault markers survive process restart and prevent
reinjection. The two-minute barrier deadline is a failure guard. A returned or
expired barrier cannot authorize a claimed process-crash experiment.

The coordinator's offline verifier checks the pinned lab envelope, host signature,
exact command/spec/profile/image identities, native CLEANED/final ACK, contiguous
durable fixture event hashes and fresh zero-resource inventory, released root
cgroup, original QEMU/shim witnesses, block/device/mount/network/storage absence.
Only then is `result.json` written with `scope:isolated-fixture-controller-cleanup`.
It always says `productionQualified:false` and `providerJobVerified:false`.
An invalid-JIT trial can prove rejection/cleanup; it cannot prove a provider job.
Use real one-attempt GitHub JIT and independently collect provider job/run facts
for provider coverage. Never put JIT in environment/argv or use guest artifacts
alone as isolation evidence.

## Power loss, recovery and cleanup

Power-loss fencing exits **2**, including when fencing succeeds. It is not a
positive recovery qualification. Boot/Docker-peer changes require actual
administrator resynchronization, independently signed peer recovery approval,
and signed cleanup-only storage reconciliation if device numbers changed.
Retain the native journal/anchor, original host key, pool owner/index, block and
cgroup tombstones and off-VM barrier. Use the existing reviewed administrative
peer/storage recovery protocol; never edit `bootId`, session epoch, endpoint,
database rows, evidence or signed profile to make a test resume. Human review and
production signatures cannot be generated by this lab harness. Positive
post-power-loss recovery and SaaS admission/reservation correlation remain
separate required acceptance gates until their real authorities are provisioned.
The fence-only coordinator refuses power removal during an active execution;
it has no fixture peer-recovery authority or positive post-power-loss apply path.
Run a verified baseline first so the durable physical allocation index exists.

For an aborted trial, durably write service-owner 0600 `cleanup.request.json`
inside the workstation fixture state directory, containing exact `caseId` and a
reason of 10–512 characters. Restart the same fixture/config/state if needed.
This produces an audited cleanup command; it does not invent a runtime exit or
absence proof. Run the same controller/journal to complete cleanup. Failed
prepared attempts may reach CLEANED/ACK without a two-process live-VM witness;
the result verifier deliberately refuses to count them as successful VM trials.
Coordinator shutdown stops loops only and leaves unresolved ownership intact.
Delete a provider runner only after exact native disposal and provider busy/ID
checks. Remove a test registry only by its recorded ID/label; never prune Docker.

Complete runtime, recovery and package qualification remain required before
production admission. Lab proofs do not authorize customer execution.

## Bounded resource-retirement qualification

The engineering requirements are defined in [SANDBOX-CLEANUP.md](SANDBOX-CLEANUP.md).
The acquisition domain follows original ownership throughout worker and recipient
lifetimes; it is not limited to processes currently inside one cgroup. Host administration
and privileged Docker/containerd remain trusted. This does not exclude known migrated
execution helpers or recipients from the domain. No universal arbitrary-host-root
reference guarantee is required. Preserve the original unrestricted-root failure.

The existing `broker-frozen-empty-v1` policy and F5-A results do not establish all of
these requirements. Before the F5-B physical campaign, demonstrate an enforceable,
complete boundary for shim, QEMU, virtiofsd, descendants, helpers and descriptor recipients.
Record exact runtime privileges, cgroup/mount/delegation controls, reference-transfer
channels and the mechanism which prevents escape or makes it durably fail closed.
A policy string, two-process witness or frozen-empty snapshot is insufficient.

### Existing native controls

Build an immutable Linux test executable with
`go test -c -tags runnerd_kata ./internal/katalinux`. Stage it and
`testdata/surviving_worker.c`, `testdata/retirement_acquirer.c`,
`testdata/retirement_transfer.c` root-owned beneath a protected executable directory on
the dedicated marked VM. Use a fresh private `TMPDIR` on the actual Kata metadata
filesystem and preserve all failed fixtures. Run with `RUNNERD09_REQUIRE_NATIVE_TESTS=1`,
`RUNNERD09_LIVE_LAB=1` and selector
`^TestRunnerd09LiveRetirement(AcquisitionDomain|CrashRecovery|FenceIdentity)$`.
Require all three parent tests and every subcase to execute with no skips. Record source,
executable hash, boot/DMI, filesystem device and original owner identities.

These controls exercise descriptors, O_PATH, directories, cwd/root, mmap, private
namespaces, surviving threads, forks, in-domain SCM_RIGHTS recipients, concurrent
acquisition, hierarchical freezing, original kernel cgroup identity, quarantine and
helper SIGKILL persistence. A forked holder or in-domain recipient must block retirement
while it survives, including after the opener/leader exits. This does not prove prevention
or tracking of transfers outside the domain.

Private native fixtures lack real block allocations/platform commitments. Retain their
empty frozen slices and ownership records; they cannot issue disposal evidence or claim
released execution capacity. A helper-process crash is not an installed broker crash.

### Required migration and transfer negative controls

Run these boundary controls on fresh, owned qualification resources before the physical
F5-B matrix. A test which cannot exercise its transition is incomplete, not a pass.
Use only recorded test workers and recipients; never move or kill unrelated processes.
Host-root orchestration may simulate a worker transition within these fixtures without
making arbitrary host-root references part of the product guarantee.

| Control | Required observation and result |
| --- | --- |
| Fork, exec, reparent, surviving thread | Establish each resource-capable descendant/recipient remains in the verified lifetime boundary; leader exit does not discharge ownership. |
| Migration before retirement | Attempt moving a recorded helper outside the original hierarchy while retaining an original reference; enforce denial, or durably quarantine before reclamation even if the old cgroup is empty. |
| Migration concurrent with fencing | Race an authorized fixture worker's attempted escape with retirement; either the control prevents migration or retirement fails closed. A return to the original group cannot erase uncertainty. |
| Descriptor transfer to known recipient | Pass original regular, directory and O_PATH handles using SCM_RIGHTS/inheritance; record actual receiver identity and original inode. If outside the original hierarchy, deny transfer or verify that receiver's separate enforced retirement boundary. |
| Unknown recipient | Exercise an untracked/delegated recipient and sender exit; unknown identity or handoff history must retain original ownership/quarantine and prohibit metadata/block reuse and successful disposal. |
| Transfer after controller startup | Exercise a controlled privileged sender and nonroot receiver after entry checks have run; root-private pathname denial or initial FD rejection alone cannot satisfy this test. |
| Namespace and mapping delegation | Retain references through private/hidden mounts, namespace handles and mappings; retirement must account for every permitted recipient/path, or preserve the original hold. |
| Concurrent acquisition | Overlap creation/fork/delegation/reference acquisition with the fence and actual reclamation; prove enforceable closure, not a quiet scan window. |
| Lost boundary evidence | If a monitor/tracker is used, inject missing events, overflow, unavailable state and broker restart; uncertainty must block reclamation, disposal and reuse. |
| Repeated recovery | Resume the same consumed Remove operation repeatedly with an unresolved worker/recipient; no new grant, replacement object, rewritten owner or successful certificate. |

For prevention, retain the exact attempted operation, process identity and enforcement
result. For tracked recipients, retain verifiable handoff provenance, birth/start identity,
original resource binding and the recipient boundary's retirement evidence. Do not use
PID alone, a one-time worker snapshot, guest assertions or repeated reference scans as
the lifetime authority. Any unknown recipient must remain a durable unresolved obligation.

Component negative controls must preserve original metadata inodes, raw/block owners,
allocation index and immutable VM/execution identity. Verify inability to reuse the
original identities/slots under uncertainty. Integrated controls must additionally verify
native/platform reservations remain held and the broker refuses successful disposal
publication. Only positive closure of every original boundary and independent physical
checks permits finalization. Test a legitimate subsequent execution separately; never
"repair" an uncertain original by replacing it.

### Physical interruption and finalization gate

After the boundary requirements and negative controls are satisfied, F5-B qualifies the
complete real VM, shim/helper, namespace, mount, block/loop/raw/index, reclamation,
disposal-publication and native-finalization matrix. Inject interruptions immediately
before and after every durable retirement transition, after metadata reclamation before
block disposal, after physical disposal before proof publication, and around lost final
acknowledgments. Include repeated broker restart and changed network policy during
execution/cleanup. No duplicate effects, false absence, replacement authority or premature
capacity release is allowed.

The installed-product gate uses the actual daemon/broker, original enrollment/journal,
platform transactions and real provider jobs. Verify lifetime worker completeness,
nonroot socket/metadata/cgroup/descriptor containment, exact committed operation
consumption, root-signed domain/disposal evidence and original native final ACK. Correlate
provider, platform, broker and native identities. Run the complete relevant campaign
against one immutable set of recorded executable hashes; historical candidates do not
qualify a later binary automatically.

Broker crashes/reboots must preserve original retirement state and ownership. Unsupported
boot/endpoint/boundary-monitor transitions retain quarantine/reservations. Extend existing
independent cleanup-only recovery authority when adding support; neither container absence
nor a vanished old cgroup permits adoption or release. Historical signed v1 artifacts stay
immutable; stronger domain semantics need explicitly versioned evidence.

Engineering threat-model direction alone is not implementation or production approval.
Production admission and revised #328/#315 acceptance remain open. No additional completed
release cases follow from these requirements or from native fixtures alone.

## Legacy native metadata cleanup stress

For operation timings, bounded retry behavior, large-directory coverage and the
remaining reference-fence design requirements, see [SANDBOX-CLEANUP.md](SANDBOX-CLEANUP.md).
The legacy scan-based path does not provide an atomic acquisition fence. Its
unrestricted-root diagnostic coverage requires the gate-script cases, including
`TestNativeSandboxLateReferenceAtUnlink`. This ptrace regression traces only a
fresh child, acquires O_PATH at the actual unlinkat boundary, and requires either
inode preservation with cleanup refusal or denied acquisition with complete
cleanup. Missing ptrace coverage cannot qualify. The unfenced legacy path is
expected to fail this test. Keep the failure and assertion unchanged. A passing
bounded retirement gate makes no unrestricted-root reference-tracking claim.
The helper source `internal/katalinux/testdata/late_reference_probe.c` must
accompany frozen native sources. The script retains the independent gate refusal
in `native-coverage.stderr` even when the test package fails.

Broker-backed Kata/storage migration remains incomplete. Container absence alone
cannot prove VM shutdown, block-device detachment or safe storage reuse. Keep the
original resource records and capacity held whenever disposal is uncertain.

Run the repository's native gate from a protected frozen source snapshot on the
marked disposable VM. The exact source tree and binary hashes must accompany
results; never transfer operator/signing/enrollment credentials with the source.
An isolated offline module cache may contain the existing public pinned
dependencies; VCS/authentication caches are not inputs.

```sh
export RUNNERD09_SANDBOX_STRESS=1
export RUNNERD09_SANDBOX_STRESS_FILES=4093
export RUNNERD09_SANDBOX_STRESS_WORKERS=32
export RUNNERD09_SANDBOX_STRESS_GUARDS=production-readonly
export RUNNERD09_STRESS_DOCKER_ENDPOINT=unix:///run/runnerd09-docker.sock
export RUNNERD09_STRESS_NETWORK_ID=VERIFIED_FULL_EXISTING_BRIDGE_ID
bash .github/scripts/qualify-kata-native.sh /private/fresh-native-results
```

The native selector includes all required parser/fresh-input regressions as well
as the native reference/recovery cases. Full stress runs include actual guards,
all 32 workers and both 4,096-entry scenarios; the retained case also retries
after explicitly releasing its owned reference. Repeat full invocations against
the same final source/binary and record min/median/max; do not infer P95 from a
tiny sample. Keep the 110-second deadline and report the 80-second engineering
target separately. Report complete worker/metadata/guard setup and request
latency, self CPU and allocations; overlapping exploratory worker timings are
aggregate time, not additive wall time. Preserve all failed intermediates.

Normal regression/race tests and the separately documented qualification-tagged
suite remain required. The built-release/SBOM gate is separate and cannot be
claimed without its inputs. Rerunning real Docker/Kata guest teardown also needs
an unexpired reviewed candidate/profile binding; no expired lab artifact or
native component result can replace that prerequisite or grant qualification.

`TestNativeSandboxBusyHostCleanupBudget` is an explicit disposable-host stress
test, not a production authorization envelope. Build the Linux test binary with
`go test -race -c -tags runnerd_kata ./internal/katalinux`; stage it with
`internal/katalinux/testdata/surviving_worker.c` as `testdata/surviving_worker.c`.
Run as root only on a marked lab VM under a transient systemd unit with
`RuntimeMaxSec=360s`, `TimeoutStopSec=5s`, `KillMode=control-group`,
`CPUQuota=200%`, `MemoryMax=1G`, `TasksMax=256` and a private working directory.
Set `RUNNERD09_SANDBOX_STRESS=1`,
`RUNNERD09_SANDBOX_STRESS_FILES=4093` and
`RUNNERD09_SANDBOX_STRESS_WORKERS=32`; run only this test with a 330-second test
timeout. All workers, namespaces and metadata belong to this test.

Each cleanup call has a 110-second deadline inside the observer's 120-second
client deadline. The two cases exercise 4,096 metadata entries with 32 surviving
worker processes, including four private mount namespaces and four CPU-active
workers. Unreferenced metadata must be removed within budget. An intentionally
mapped inode must prevent removal and remain intact within budget. JSON test
logs record elapsed time, load, guard calls, deadline and removal outcome.
A deadline failure keeps the performance gate open; reference checks must never
be skipped to meet it. This bounded synthetic load does not prove latency on
arbitrarily large or differently configured hosts. Archive source/binary hashes
and results separately from previous frozen qualification evidence.

Cleanup latency remains an open qualification requirement. Run the stated workload
against the final candidate and retain results outside Git. A timeout is incomplete
cleanup; preserve ownership and retry through the existing guarded recovery path.
Do not skip reference, namespace, mount, identity or durability checks to meet the
request budget.

## Broker-managed Kata lifecycle fixture

The separately tagged `TestPhaseDControllerRealDocker` fixture also exercises
broker-managed block-backed Kata when `RUNNERD_PHASE_E_SEED` names an existing
unqualified lab envelope. It preserves that pool's original evidence/journal
owner and allocation index. Build both the execution test executable and broker
with `runnerd_broker_qualification,runnerd_qualification,runnerd_kata`, record the
commit and binary hashes, and use only the marked disposable VM. Its issuer,
provider and database are explicit fixtures; this test does not qualify the
shipped daemon, a real provider, or production admission.

Set `RUNNERD_D2_SYSTEMD=1` and `RUNNERD_D2_BROKER_BINARY` to the root-protected
broker executable for process-crash qualification. The temporary Kata broker
service receives only the existing signed pool/evidence/device/sandbox write
paths, loop-control/loop-block and pinned backing-device access, and the storage
capabilities needed for that lifecycle. The controller keeps an empty capability
set, private devices, masked runtime sockets, masked Kata ownership/storage and
no supplementary groups. Retained unit bodies and journals are evidence; these
qualification units do not replace shipped packaging.

Use `RUNNERD_D2_CRASH_OPERATION` (`CreateExecution`, `StartExecution`, or
`RemoveExecution`) with the existing `RUNNERD_D2_CRASH_POINT` to select one exact
root-owned, durably consumed SIGKILL boundary. Reconciliation must retain the
original physical ID and authority. A before-effect create/start uses
`RUNNERD_D2_EXPECT_QUARANTINE=1`; a before-start case additionally uses
`RUNNERD_D2_EXPECT_OWNED=1`. Those cases intentionally retain unresolved records
and reservations for external reboot/power-loss observation.

Historical Kata profiles support separately authorized cleanup-only boot recovery
when original protected Kata/storage anchors exist. New retirement-policy profiles
remain quarantined across boot changes pending their separate qualification. Docker-only boot recovery
remains forbidden for Kata. Container absence never discards the original block
allocation, operation or reservation. Missing anchors and ambiguous creates stay
held; do not clear them to make another test fit. After broker-verified disposal,
the actual unprivileged daemon's `--recovery broker-finalize` path reconciles the
original native CLEANED/outbox/final ACK through the existing platform authority.
This is explicit operator recovery, not qualified automatic boot orchestration.

`RUNNERD_E2_HOLD_BLOCK=1` adds an externally held reference to the original raw
inode during one Kata lifecycle. The parent must observe broker quarantine,
original inode/index retention and an unreleased native reservation before it
closes the reference. The controller then reconciles the same consumed removal;
no replacement allocation or renewed mutation authority is permitted. This is
one retained-reference test, not qualification of all reference races.

For cross-boot preservation, the held snapshot includes the original native and
broker hashes, pool owner/index, prepared physical/cgroup witnesses and a full
raw-disk hash. Active allocations live in `block-slots.json`; per-execution
`.block.json` files are released tombstones, not the active ownership source.
`TestKataBootRetainedLab`, with `RUNNERD_E2_HELD_STATE` set to that protected
snapshot, observes the same marked VM after an actual boot/peer change using a
read-only engine. It must retain the original operation, raw inode/data, pool
reservation and native reservation, and reject Docker-only recovery. A passing
result proves preservation and denial, not automatic Kata reboot recovery.
