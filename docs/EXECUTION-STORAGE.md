# Standard Docker execution storage

New Standard executions use `linux-github-disk-v1`. Each original installation,
execution, generation, attempt and spec has one private disk directory containing
`workspace`, `home`, `tmp` and `diagnostics`. These are writable binds at
`/runner/_work`, `/home/runner`, `/tmp` and `/runner/_diag`. The container writable
layer is also execution-specific and is reclaimed by owned Docker removal.
There are no mandatory filesystem quotas and no shared writable caches.
`storageBytes` is an admission budget, **not an enforced byte limit**.

Keep execution admission disabled until this exact template, image, service and
storage layout pass independent qualification. The image remains the approved
process-only GitHub image: the execution template changes its storage mounts,
not its bootstrap protocol. Qualification must explicitly sign the disk template;
a previous tmpfs-template approval does not authorize it.

## Operator provisioning

Customers choose their filesystem layout, Docker storage backend, capacity and
monitoring policy. A workspace, Docker data and protected journal may use the
same filesystem. No dedicated disk/partition, quota or snapshotter is required.
Cleanup cannot prevent an active job from filling shared storage. Runnerd never
formats storage, changes Docker units/configuration or cancels work for disk use.

Provision a private execution directory for the nonroot service account, for
example on the existing root filesystem:

```bash
sudo install -d -o neticora-runnerd -g neticora-runnerd -m 0700 \
  /mnt/neticora-runners/executions
```

`/mnt/neticora-runners` is an ordinary example directory, not a mount requirement.
Set `execution.storageRoot` to that absolute path in the existing complete inactive
configuration. Directory ownership, safe ancestors and separation from credentials,
trust and the journal remain security requirements; separate filesystems do not.

Optional top-level `observationPaths` adds up to 32 absolute paths for filesystem
measurements. Default observations include `/`, the journal, configured workspaces
and DockerRootDir when available. Paths can share the same filesystem; observations
are not additive. There is no mandatory Docker/containerd backing-path list.
Legacy `execution.runtimeStoragePaths` remains an optional observation list;
`execution.minRuntimeFreeBytes` is accepted for upgrades but ignored by admission.

The shipped unit permits writes to the default execution root. A custom root
requires a reviewed systemd `ReadWritePaths` drop-in. Do not relax protection of
the journal, credentials or host filesystem. The root must exist with safe ancestors and private ownership. Trust, bootstrap
and journal directories must not overlap it. Filesystems must support the required
ownership, confined-open and durability operations; uncertainty fails closed.

## Cleanup and recovery

The protected SQLite journal commits allocation intent before mkdir and pins the
original filesystem/inode identity before creating the four job directories.
The enclosing directory is never mounted into a job. Existing names without a
committed inode are ambiguous and quarantined, including a crash in that gap.
No retry allocates a replacement name. Mount IDs are not persisted as durable
identity: systemd recreates its service mount namespace on restart. Filesystem
and inode identity persist, and every child open rejects mount crossings.

Normal provider post-steps and required artifact/log delivery must complete
before the platform authorizes cleanup. GitHub's runner performs workflow uploads;
Runnerd is not an additional artifact uploader. Authorized cancellation may
interrupt work. Required external evidence retention remains the provider/
platform's responsibility; container exit alone is not cleanup authority.

The controller records cleanup intent, verifies the original Docker configuration
and ownership, stops as authorized, and requires the original platform cleanup
command before removal. Successful remove is followed by authoritative runtime
reconciliation, private-namespace mount checks, absence of a populated original
systemd Docker cgroup, and checks for other containers binding the storage.
Only then does fd-relative deletion proceed. This boundary assumes trusted Docker
and host administration, the Standard private-namespace template and cgroup v2
with the systemd driver/default cgroup parent. Other layouts fail closed. It is
not the paused Runnerd09/#328 acquisition-domain qualification and does not claim
to discover arbitrary trusted-host descriptor recipients or copied mounts.

Deletion rejects mount crossings (`openat2`/`RESOLVE_NO_XDEV`), path traversal,
changed inode identities, unknown outer entries and files owned by another UID.
Symlinks are unlinked without following them. Permission failures are quarantined;
there is no privileged deletion helper or root fallback. Operations are bounded
and cancellable; very deep/large trees may require operator investigation.

The journal commits `retiring` before unlinking. Interrupted authorized retirement
resumes that original inode/name; durable `disposed` evidence is recorded only
after verified absence and parent fsync. A journal guard blocks `cleaned` events
and local reservation release until disposal. Existing final platform event/ACK
ordering still controls platform capacity. Lost responses retain original IDs,
fences and obligations. A missing directory while merely `allocated` is not proof
of disposal. Unknown directories stop readiness and are never deleted by age.

Disposed rows remain permanent replay fences; the active scan bounds outstanding
records rather than all retired history. There is no automatic journal reset or
compaction. New legacy tmpfs admissions are rejected; previously accepted legacy
commands and immutable plans remain recoverable under their original semantics.
Docker restart/endpoint change and unsupported reboot transitions retain the
existing authoritative recovery fence, never silently adopt a new daemon.

There is no mandatory disk-usage/free-space admission threshold and no automatic
cancellation based on utilization. The protected journal's default free-space
margin is zero; explicitly configured journal maintenance/headroom options remain
operator choices. Journal/outbox size bounds, authenticated qualified capacity,
CPU/memory/PID/concurrency controls and original ownership fences remain intact.
An actual failed durable write, failed fsync, uncertain anchor or unverifiable
cleanup keeps the original obligation and prevents unsafe acknowledgment/reuse.
Never reset a journal or force-release a reservation after disk exhaustion.

[Resource observations](RESOURCE-TELEMETRY.md) provide timestamped measurements
for customer monitoring. They neither qualify a host nor determine admission.

## Package compatibility

This change upgrades the recovery database to schema 4, adding immutable execution
storage records. Older binaries must reject the newer schema. Rollback requires a
separately reviewed compatible binary; never downgrade `user_version`, drop storage
records, restore an earlier journal over active obligations, or delete directories
to make an upgrade succeed. Enrollment keys and original #330 evidence are outside
this storage lifecycle and are not changed by it.
