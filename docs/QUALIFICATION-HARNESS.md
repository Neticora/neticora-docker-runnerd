# Runnerd09 configuration and qualification harness

The ordinary daemon accepts only independently qualified production profiles.
It must not receive invented acceptance references to bootstrap its own tests.
`runnerd-qualification` is a separate Linux amd64 binary built with
`runnerd_qualification`. Its distinct Ed25519 lab envelope requires
`qualified:false`, empty acceptance, a separate pinned lab authority, a private
HTTPS control-plane address and exact VM/boot/tenant/host/pool/config bindings.
Ordinary `Open`/`katalinux.Load` reject this envelope even in a tagged binary.
No lab result grants production or SaaS admission.

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

All 48 Runnerd09 acceptance cases, independent security approval and production
host qualification remain explicit. A lab proof is useful evidence, not closure
of the epic or permission to enable customer execution.
