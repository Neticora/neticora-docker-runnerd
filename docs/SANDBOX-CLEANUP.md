# Sandbox cleanup

Production admission remains disabled. Issues #328 and #315 remain open.
The bounded acquisition-domain direction is accepted in principle. The requirements
below govern engineering; implementation conformance, revised #328 acceptance and
production qualification remain unapproved. F5-B's physical fault campaign is gated
on the acquisition boundary and its negative controls.

## Acquisition contract

The domain follows original resource ownership throughout its lifetime, independently
of current cgroup membership. It includes every broker-managed process capable of
accessing protected sandbox resources: shim, QEMU, virtiofsd, descendants, surviving
threads, delegated helpers and recipients of their descriptors or other references.
A worker does not leave the domain by moving cgroups, losing its parent, changing
namespaces, or passing its last descriptor elsewhere. An unknown recipient is an
unresolved ownership obligation.

The contract protects against malicious CI workloads, compromised nonroot Runnerd
and incomplete retirement of broker-managed workers. Customer host administrators
and privileged Docker/containerd remain trusted. Universal detection of references
deliberately retained by arbitrary trusted host processes is not required. Known
execution helpers and recipients cannot be excluded as trusted host administration
merely because they escaped the original cgroup. The exact runtime's worker trust,
privilege and delegation assumptions must be stated and qualified explicitly.

Only the broker may request privileged runtime lifecycle operations. The controller
must have no Docker/containerd socket, inherited privileged descriptor, host metadata
descriptor, cgroup delegation or ability to thaw/migrate host workers. Entry checks
must reject privileged inherited handles, including handles hidden in stdio. Entry
checks and root-private pathname permissions do not revoke a descriptor transferred
after startup; the acquisition boundary must remain enforceable for the whole lifetime.
Protected runtime metadata and evidence must remain beneath root-owned 0700 ancestors.
Those pathname protections complement, but do not establish, lifetime reference control.

An acceptable acquisition boundary must establish all of the following:

- Every resource-capable worker and delegated helper belongs to a verifiable lifetime
  boundary tied to the original execution, generation and immutable ownership. Fork,
  exec, thread survival, reparenting and namespace changes cannot create an unaccounted
  acquisition path. A snapshot of shim/QEMU or one observation of virtiofsd is insufficient.
- Worker migration outside the original cgroup is prevented by enforceable controls,
  or the transition causes retirement to fail closed before reclamation. Later return
  to the cgroup cannot erase an unresolved escape or possible delegation.
- Descriptor/reference transfer outside the verified domain is prevented, or each
  recipient is tracked through an independently verifiable retirement boundary. This
  includes directory and O_PATH descriptors, inherited handles and namespace references.
  Unknown recipients or unverified transfer channels require quarantine.
- New workers, delegated access and reacquisition of the original resources are fenced
  before reclamation. The lifetime boundary must also account for existing references,
  including mappings and private mount namespaces. A frozen, empty original cgroup is
  a useful kernel observation, never sufficient proof of complete domain retirement.
- Loss of evidence about worker membership, migration, delegation or acquisition paths
  is uncertainty. If enforcement uses a monitor, gaps, overflow, restart discontinuity
  or unavailable state cannot be treated as proof that no transfer or escape occurred.

Repeated procfs/reference scans, delays, rename and missing pathnames cannot establish
these properties. A signed runtime/profile declaration must name an enforced and
qualified mechanism; its policy string alone supplies no kernel boundary.

## Durable retirement and reuse

The broker consumes the exact platform-committed original `RemoveExecution` authority
and records durable retirement intent before asking trusted Docker to remove that
object. Original operation, profile, container, spec, generation, cgroup identity,
process witnesses, metadata inodes and storage ownership remain bound throughout.
There is no replacement execution, backfilled owner, journal reset or new authorization
service. Permanent tombstones prevent reuse of the original execution/resource identity.

Reclamation requires positive evidence that every in-scope acquisition path is closed
and every possible resource holder is retired or prevented from acquiring/using the
protected resources. This obligation extends beyond the original cgroup when a tracked
recipient or migrated worker exists. Unknown workers/recipients leave the original
resource owned and quarantined. Do not unlink metadata, release a block allocation or
issue successful disposal evidence on a frozen-empty observation alone.

Retirement intent, acquisition fencing, reclamation and verified disposal are separate
durable states. Immediately before a destructive step, the original physical identity
and the enforceable acquisition boundary must still hold. Metadata and block-storage
obligations have separate owner, inode, mount, loop/device and physical absence checks.
A metadata pathname disappearing does not release a storage slot or prove disposal.

Any uncertainty preserves the last durable phase, quarantine, original metadata/block/
VM identity and native/platform reservations. No metadata, block allocation, VM identity
or storage capacity may become reusable while original ownership or reference-domain
retirement is uncertain. Unrelated executions cannot receive the original identity or
an uncertain slot. Local allocator reuse additionally requires durable proof of the
original domain's retirement and the slot's physical reuse conditions.

A durable reclamation seal must revoke deletion authority before the acquisition
barrier is lifted. After that seal, retries may verify the original physical absence
and finish the original release; they must not delete replacement resources or repeat
reclamation against an unprotected domain. Disposal becomes durable only after every
required original physical and acquisition-domain check succeeds.

## Recovery

Broker crashes and host reboots must preserve original retirement state, outstanding
reference-domain obligations and resource ownership. Recovery reconciles the original
consumed operation. It neither creates a replacement resource nor silently adopts the
current runtime, cgroup or storage as the original one.

Missing cgroups after reboot, changed kernel device/inode numbers, vanished workers,
expired lab artifacts and missing Docker containers do not discharge an obligation.
Unsupported boot/endpoint/monitor transitions fail closed, retaining quarantine and
reservations. Extend the existing independently authorized cleanup-only boot-recovery
protocol when adding support; do not create a competing recovery authority. A recovery
grant cannot create/start work or rewrite original owners.

## Evidence and finalization

Independent broker disposal evidence must bind the original operation, immutable
execution/resource identity and verifiable retirement outcome, including completeness
of the acquisition domain. The platform must enforce the policy from the original
signed admission and reject stripped, substituted or insufficient domain evidence.
An old proof cannot acquire stronger semantics through a documentation change.

Physical removal, domain retirement, signed disposal verification and native finalization
remain separate. Platform verification marks the exact committed obligations disposed;
only the original native final acknowledgment releases the execution reservation.
Successful Docker removal, an empty cgroup or a missing raw file never substitutes for
those steps. Unknown ownership/recipients must prevent a successful disposal certificate
and premature capacity release, including after repeated recovery.

## Current implementation limits

`broker-frozen-empty-v1` is the existing experimental signed policy. Its records bind
original identity and use `INTENT`, `FENCED`, `RECLAIMING`, `RECLAIMED`, `DISPOSED`, with
quarantine retaining the last durable phase. Its frozen-empty checks compare the actual
kernel device/inode and opened cgroup handle to the original owner. The implementation
seals `RECLAIMED` before thaw/stop because systemd 259 refuses to stop a frozen unit.
These controls and the original block-owner checks remain useful engineering evidence.

The current durable physical process witnesses identify shim and QEMU. Existing tests
cover surviving threads, forked workers and descriptor recipients that stay inside the
original hierarchy. They do not establish complete lifetime accounting for virtiofsd/
helpers, prevent or track privileged-worker migration, or track outward descriptor
transfer. The current v1 proof therefore does not establish conformance with the full
contract above. Do not count old F5-A results, or issue new qualification approval on
their basis, as satisfying these missing requirements.

`internal/workerboundary` supplies a separate acquisition-boundary component. A
protected `runnerd09-worker-domain-v1` record binds the original operation, owner,
boot, namespace-init birth, PID/mount namespace inodes and helper/policy hashes.
Its `INTENT`, `READY`, `RETIRING`, `RETIRED` states never replace the original
physical/storage obligations or authorize disposal. Ambiguous creation cannot adopt
another namespace. A boot change cannot prove retirement.

Workers and transfer guardians inherit one original kernel PID namespace, including
descendants moved to other cgroups. Retirement signals only the verified original
init through its pidfd and waits for the kernel lifetime barrier. PID-namespace
escape, asynchronous descriptor-transfer APIs and replacement seccomp listeners are
denied. `sendmsg` is emulated using copied buffers and file descriptions captured
from the notifying thread's pidfd; inspected syscalls are never resumed. Rights
are limited to immutable connected Unix stream/seqpacket peers visible inside the
original namespace. Socket, namespace, pidfd and unknown anonymous-descriptor relay
are denied; supported ordinary files, directories, pipes and eventfds may remain
inside the domain. Losing a guardian leaves kernel notification failure, not an
unfiltered syscall fallback. A failed guardian latches a protected same-boot fault
and the original namespace refuses replacement acquisition. The broker durably
records quarantine with the original phase/owner. A control path on `/run` does
not promise power-loss persistence; the durable original boot/ownership record
still rejects unsupported reboot cleanup. Authorized retirement checks the original birth even
when acquisition health has failed; it cannot substitute another namespace.
Guardians remain inside the same lifetime boundary.

`execve` resets dumpability. The helper therefore seals the worker's real,
effective and saved UID at zero, denies user-namespace entry/creation and rejects
ptracer delegation. Filesystem UID/GID operations are not silently treated as
proof of a changed process identity. This is a narrow host-worker ABI, not a claim
that every Kata/virtiofsd configuration supports it. The guest has its own kernel.
An outside unprivileged controller must not acquire worker descriptors through
procfs or process-extraction APIs after exec or filesystem credential changes.

`runnerd09-worker-preflight-apparmor-v1` is a separate native confinement policy.
It pins explicit executables, keeps private directory guards read-only, restricts
writes to owned metadata/scratch/logs, and denies broker state, privileged runtime
sockets, abstract connect and unapproved exec. Pathname Unix sockets use file
mediation; abstract/anonymous sockets have separate rules. Root-directory read
needed by the qualified namespace-inode representation is not recursive host
filesystem read. The policy grants no mounts, VM devices or runtime admission.
Its negative fixtures cannot approve an untrusted Kata workload or replace an
independent security review.

This component is not connected to installed broker admission or disposal. Native
fixtures deliberately use a broad AppArmor profile to isolate kernel mechanism
tests; that profile is unsuitable for executing untrusted workers. Before runtime
integration, independently pin an enforcing per-domain filesystem/IPC policy that
protects broker records, helper binaries, host policy, privileged endpoints and
unsupported kernel-mediated delegation paths. Verify every shim, QEMU, virtiofsd
and helper enters the boundary before acquiring protected resources. Preserve the
original committed-operation/journal ordering and version the signed admission and
disposal evidence independently. Actual block-backed VM execution, complete runtime
ABI, installed service capabilities, recovery and unsafe reuse remain qualification
gates. Neither native fixture success nor shim task-service startup closes them.

Keep historical signed artifacts, original ownership and completed evidence immutable.
A stronger domain-evidence format must be explicitly versioned and independently
verified rather than reinterpreting old v1 signatures. Existing unresolved obligations
remain owned; where the complete boundary cannot be proved, the required behavior is
quarantine. New-policy cross-boot cleanup remains unsupported and fails closed.

Metadata traversal remains bounded: 64 names per read, 4,096 entries per captured
directory per request, maximum depth 32, parent fsync after each removal. These limits
are operational bounds, not acquisition fences. Standalone execution and signed
standalone recovery use the direct LVM and block cleanup paths. Historical broker
recovery reaches physical absence verification. Without a retirement fence it
preserves the original ownership if metadata remains, and verifies references and
durable absence after the original runtime removes the metadata. The unfenced
mutating scanner is confined to native diagnostics.

## Qualification

F5-A results qualify only the controls actually exercised. Passing native acquisition
fixtures or one live worker-placement snapshot cannot close the missing lifetime,
migration and outward-transfer requirements. Complete the negative controls in
[QUALIFICATION-HARNESS.md](QUALIFICATION-HARNESS.md#bounded-resource-retirement-qualification)
before the full F5-B physical interruption/unsafe-reuse matrix.

F5-B must test process migration, descriptor passing, concurrent acquisition and
interrupted retirement with the original metadata/block ownership, disposal and capacity
assertions. Crashes before/after every durable transition, metadata-before-block disposal,
proof publication, final acknowledgment, repeated broker recovery and unsupported reboot
must not permit false disposal or unsafe reuse. Repeat the relevant end-to-end campaign
against one immutable candidate and retain exact binary/profile/evidence identities.

The original `TestNativeSandboxLateReferenceAtUnlink` remains unchanged. Its F5 failure
on the actual Kata metadata filesystem remains retained outside Git. It demonstrates
that repeated scans cannot provide an unrestricted-root reference guarantee. Do not
delete its assertion, report it as fixed or silently convert it into a passing test.
No additional acceptance cases or production approvals follow from revising this contract.
