# Sandbox cleanup

Production admission remains disabled. Issues #328 and #315 remain open.

## Acquisition contract

New broker-managed Kata executions require the independently signed profile policy
`broker-frozen-empty-v1`. The adversarial domain contains CI workloads, the
unprivileged controller and execution workers inside the original protected host
cgroup, including their surviving threads and private mount namespaces. Host
administrators, the system manager and privileged Docker/containerd are trusted.
This is not a guarantee about references deliberately retained by arbitrary root
processes outside the execution domain.

Only the broker may request privileged runtime lifecycle operations. The controller
must have no Docker/containerd socket, inherited privileged descriptor, host
metadata descriptor, cgroup delegation or ability to thaw/migrate host workers.
The signed runtime tuple must place all execution workers in the original owned
cgroup. A runtime that transfers resource handles to uncontrolled workers does not
satisfy this contract. Runtime and metadata roots remain protected by a root-owned
0700 ancestor. These installed containment and placement requirements need live
qualification; a signed policy string alone proves none of them.

## Durable retirement

After consuming the original committed `RemoveExecution` authority, the broker
writes an `INTENT` tombstone before asking trusted Docker to remove that exact
object. The tombstone binds the operation, profile, container, spec, generation,
original cgroup owner/boot/device/inode, captured sandbox inodes and process
witnesses. It prevents subsequent preparation, launch and replacement capture.
Historical profiles remain readable for original cleanup; fresh admission requires
the new policy. There is no reset, ownership adoption or replacement grant.

Before broker reclamation the original systemd slice is frozen. The broker verifies
the owner, boot, kernel inode and hard limits, `cgroup.freeze=1`,
`cgroup.events:frozen=1` and hierarchical `populated=0`. Frozen populated groups
remain quarantined; the broker does not kill or adopt unidentified workers. The
trusted original runtime/operator must retire those workers before the same
operation can resume. No thaw is issued before durable `RECLAIMED` has revoked reclamation authority.

Successful kernel observation is persisted as `FENCED`, followed by durable
`RECLAIMING` before unlink or storage release. Reclamation uses the live fence and
fresh original inode/filesystem/mount checks. It does not use repeated descriptor
or namespace scans as its acquisition barrier. Legacy scan-based cleanup remains
for immutable old obligations and as a diagnostic comparison only.

Metadata traversal is sequential: 64 names per read, 4,096 entries per captured
directory per request, maximum depth 32, parent fsync after each removal. Original
block allocation and metadata retirement are separate obligations. Storage still
requires its original owner, mount, loop, raw inode and physical release checks.
Any uncertainty retains original ownership, the last durable phase, a quarantine
flag and the native/platform reservation. A missing path never grants capacity.

After metadata and block disposal, durable `RECLAIMED` revokes reclamation
authority. Only then may the original empty slice be explicitly thawed and
stopped (systemd 259 refuses to stop a frozen unit). No reclamation is allowed
after this barrier is removed. A lost response after slice release permits only read-only verification
that the original metadata, block allocation and cgroup are already absent.
`DISPOSED` is durable only after all physical checks succeed. Tombstones remain
permanent; compaction must preserve their replay fences.

## Evidence and finalization

The broker's independent disposal signature covers the retirement policy, original
remove operation and canonical durable retirement-record hash. The platform derives
the required policy from immutable signed admission and challenges that policy.
Stripped, substituted or unexpected retirement evidence is rejected. Ordinary
Docker and historical proofs retain their original wire representation.

Physical removal and retirement do not release a reservation. Platform verification
marks exact committed obligations disposed; the original native final ACK still
controls capacity release. Boot/endpoint changes of new-policy resources remain
quarantined pending a separately qualified retirement recovery path.

## Qualification

F5-A qualifies the bounded acquisition domain, worker references, namespace/thread
survival, concurrent acquisition, durable interruption/restart and quarantine.
Only after that gate passes may F5-B run the real VM/mount/block/reclamation/
publication/final-ACK interruption matrix. Component results cannot substitute for
installed-service or real execution qualification.

The original `TestNativeSandboxLateReferenceAtUnlink` remains unchanged. Its F5
failure on the actual Kata metadata filesystem is retained outside Git. It proves
that repeated scans cannot provide an unrestricted-root reference guarantee. It
must not be deleted, reported as fixed, or silently converted into a passing test.
The bounded replacement contract and acceptance evidence require explicit review.
