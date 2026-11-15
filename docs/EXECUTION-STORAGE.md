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

Use a dedicated customer-managed filesystem for job data and Docker's actual
writable backing storage, separate from the OS and protected Runnerd journal.
Cleanup reclaims finished work; it cannot stop an active job filling a filesystem.
Runnerd neither formats storage nor reconfigures or restarts Docker.

Provision the execution root for the configured nonroot service UID/GID:

```bash
sudo install -d -o neticora-runnerd -g neticora-runnerd -m 0700 \
  /mnt/neticora-runners/executions
```

Add these fields to the existing complete, **inactive** execution configuration:

```json
{
  "storageRoot": "/mnt/neticora-runners/executions",
  "runtimeStoragePaths": ["/var/lib/docker", "/var/lib/containerd"],
  "minRuntimeFreeBytes": 268435456
}
```

The example backing paths are not discovery or installation instructions. An
administrator/independent qualifier must verify the running Docker backend and
containerd configuration and replace them with **all actual backing paths**.
With a containerd snapshotter, Docker's `DockerRootDir` alone is insufficient.
Unreadable, missing, low-space or low-inode paths block new work. These checks
only observe free space; they do not prove a quota or whole-host storage bound.
Custom snapshotter relocation or unverified backing-path lists are unqualified.

The shipped unit permits writes to the default execution root. A custom root
requires a reviewed systemd `ReadWritePaths` drop-in. Do not relax protection of
the journal, credentials or host filesystem. The root must already exist on a
supported local durable filesystem, with safe ancestors and private ownership;
trust, bootstrap, Docker backing paths and journal must not overlap it.

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

Low space/inodes stop new admission; below 64 MiB or 128 free inodes requires
operator intervention. Authorized cleanup/reporting remain
available. Space pressure is also checked during reconciliation of running work.
Preserve protected recovery evidence on disk-full errors; never fabricate cleanup
success or force-release a reservation. Inspect the reported pressure/quarantine
reason and the original journal before any operator recovery action.

## Package compatibility

This change upgrades the recovery database to schema 4, adding immutable execution
storage records. Older binaries must reject the newer schema. Rollback requires a
separately reviewed compatible binary; never downgrade `user_version`, drop storage
records, restore an earlier journal over active obligations, or delete directories
to make an upgrade succeed. Enrollment keys and original #330 evidence are outside
this storage lifecycle and are not changed by it.
