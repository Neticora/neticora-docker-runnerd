# Standalone Docker/Kata Runnerd

The AMD64 package targets Ubuntu 26.04 with systemd. The installed service runs
as trusted host root and uses the native `/run/docker.sock`. Workflows run in
individual Kata VMs and use private guest Docker and BuildKit.

## Prepare host and storage

Provision local Docker Engine and containerd, Kata runtime-rs with QEMU/KVM,
cgroup v2 with systemd, and LVM Thin. Verify `/dev/kvm` and load the loop and
device-mapper modules before service activation. Configure Docker with the
reviewed Kata runtime mapping and enough free space for the signed budget.
Mount the dedicated ext4 execution and runtime volumes before starting
Runnerd. Place the mounts beneath `/var/lib/neticora-runnerd-kata` so the
packaged unit orders startup after them. Use a separate thin pool with adequate
data and metadata capacity for cache generations.

Provision root-owned `kata` and `kata-containers` directories on the dedicated
runtime ext4 volume. Bind them to `/run/kata` and `/run/kata-containers` before
containerd and Docker start. Include `kata` and
`kata-containers/shared/sandboxes` beneath the runtime volume in the signed
sandbox roots. Kata uses `/run/kata/<id>/state.json` to restore the sandbox and
remove its share. Persist both directories on the same qualified volume.

After adding the dedicated ext4 runtime volume to `/etc/fstab`, add its bind
mounts with a dependency on the backing volume.

```fstab
/var/lib/neticora-runnerd-kata/runtime/kata /run/kata none bind,x-systemd.requires-mounts-for=/var/lib/neticora-runnerd-kata/runtime 0 0
/var/lib/neticora-runnerd-kata/runtime/kata-containers /run/kata-containers none bind,x-systemd.requires-mounts-for=/var/lib/neticora-runnerd-kata/runtime 0 0
```

Add the following systemd drop-in to `docker.service` and, if installed
separately, `containerd.service`. The Runnerd unit requires the same mounts.

```ini
[Unit]
Requires=run-kata.mount run-kata\x2dcontainers.mount
After=run-kata.mount run-kata\x2dcontainers.mount
```

Run `systemctl daemon-reload` after provisioning the mount and service units.
Configure the dedicated cache thin pool for LVM autoactivation before starting
Runnerd and verify the expected pool UUID and active state after boot.

Keep the durable journal, enrollment identity, signing trust and execution
evidence on persistent host storage outside guest-visible mounts. Start the
control plane on an empty PostgreSQL database, then provision a fresh
enrollment, journal and dedicated execution pool. Keep the original journal
and pool together for crash and reboot recovery. A missing or corrupt index
blocks admission and resource reuse.

## Install and enroll

Verify the candidate hash and install with `sudo dpkg -i PACKAGE.deb`. The
maintainer script prepares protected directories and leaves activation to the
operator. Obtain a one-use pool enrollment token and place it in a root-owned
0600 file. With an independently verified tenant UUID, enrollment ID, HTTPS
address and private CA, run:

```sh
sudo /usr/bin/runnerd-enroll \
  --endpoint 'https://CONTROL_PLANE/api/v1/runner-hosts' \
  --tenant-id TENANT_UUID --installation-id enrollment:ENROLLMENT_UUID \
  --state-dir /var/lib/neticora-runnerd-kata/enrollment \
  --ca-file /etc/neticora-runnerd-kata/control-ca.pem \
  --token-file /path/to/root-only-token \
  --runtime-endpoint unix:///run/docker.sock --standalone
```

Install root-owned mode-0600 configuration, the independently signed qualified
standalone descriptor and its public verification key under
`/etc/neticora-runnerd-kata`. Set the execution journal,
credential and evidence paths to the matching package directories. Set guest
bootstrap root to `/run/neticora-runnerd-kata/bootstrap` and the descriptor's
execution device directory to `/run/neticora-runnerd-kata/devices`. Pin the
independently verified guest image and use the approved image trust, thin pool,
workflow authorization and runtime tuple. Install the independent peer recovery
public key as `/etc/neticora-runnerd-kata/recovery.pub`.

Start the managed unit with `sudo systemctl start neticora-runnerd`.
The platform must accept the separately signed host qualification. Verify
`sudo runnerctl status`, then explicitly resume with `sudo runnerctl resume`
when the host is ready to accept signed executions.

## Reboot, upgrade and removal

On a new boot the service waits for the current boot's independently signed
and platform-committed peer approval. Use the existing recovery inspect,
proposal and approval flow. Atomically deliver the signed input to
`/var/lib/neticora-runnerd-kata/recovery/approval.json` with mode 0600. The
running unit applies it without a manual recovery invocation. The host remains
drained until a new signed launch qualification is installed and resumed.

If cleanup reports remaining Kata metadata, preserve the original runtime
volume and sandbox state. Retry through the original Docker and containerd
lifecycle. A successful shim delete response alone does not prove physical
disposal. Runnerd keeps the reservation until the signed recovery verifies
the original sandbox and storage are absent and records the final ACK.

Drain and stop the service before any replacement or removal. The maintainer
scripts refuse to replace a running service. Removing the package preserves
the journal, enrollment credentials, signed qualification and all owned
volumes. Retiring a host and releasing its storage is a separate operation.

After removal, systemd may retain a failed state for the removed unit. If
reinstall is rejected, confirm the drained service has zero MainPID and
ControlPID. Clear the stale state with
`sudo systemctl reset-failed neticora-runnerd.service`, recheck the unit, and
then reinstall. To restore automatic activation on boot after a remove and
reinstall, run `sudo systemctl enable neticora-runnerd.service`. The signed
recovery and launch qualification requirements still apply on the next boot.
