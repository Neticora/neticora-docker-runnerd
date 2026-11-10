# Manual UI-token registration and pool execution

Use `runnerd-linux-amd64.tar.gz` on x86-64 Linux. The arm64 archive supports
registration; current execution controller remains Linux amd64 only. These are
foundation candidates, not production-qualified releases.

## Register a host

Extract the archive on the Docker host. Use the same dedicated non-root account
for enrollment and the daemon. Provision its private enrollment directory outside
the journal, for example:

```sh
sudo install -d -o neticora-runnerd -g neticora-runnerd -m 0700 \
  /var/lib/neticora-runnerd-keys/manual-enrollment
sudo -u neticora-runnerd ./packaging/enroll-interactive.sh \
  https://platform.example.com/api/v1/runner-hosts TENANT_UUID \
  /var/lib/neticora-runnerd-keys/manual-enrollment
```

The binaries and wrapper must be readable/executable by that account; do not run
from a root-only home directory. Create the account using the packaged sysusers
configuration when installing on a clean host.

In the UI, create/select a **customer-host pool**, generate an enrollment token
bound to that pool, and paste it at the hidden prompt. Use the canonical tenant
UUID. No administrator bearer is required on the runner host.

The command generates an Ed25519 key locally, durably saves the identical
request before sending, registers the host, exchanges a signed assertion, and
fetches authenticated platform configuration. Its JSON output contains the host
ID, session epoch and platform admission status, never the token or private key.
It does not enable admission, start Docker resources or start the daemon.

If a response is lost, rerun the **same command and state directory**. Do not
remove state or generate another key. Once a receipt is durable, repeated runs
reuse it and check authentication/configuration without enrolling again. A boot
change requires explicit operator resynchronization; this helper does not bypass
session-epoch or Docker-peer recovery. Keep this directory private (0700) and its
files private (0600); it includes the recovery key and original enrollment token.
After enrollment, revoke the original UI token when appropriate; retain the
protected recovery state until the host itself is revoked.

For a private CA, append `--ca-file /absolute/service-owned-0600-ca.pem`.
Certificate and hostname verification remain enabled.

## Connect the registered host to execution

Registration alone is insufficient for pool execution. An operator must verify
pool authorization, provision policy/capabilities, pin the signed runner image
and trust roots, and provide the independently signed host/Kata qualification.
Kata additionally requires the qualified runtime/storage tuple and privileged
observer. Existing production admission and security checks remain mandatory.

The current enrollment API does **not** return installation ID. Obtain that ID
from the authorized platform operator for the exact host ID (do not invent it).
Then rerun enrollment with the same protected directory and append:

```sh
--installation-id PLATFORM_INSTALLATION_ID \
--runtime-endpoint unix:///run/qualified-docker.sock
```

This performs a read-only Docker identity probe and writes `identity.json` once,
using the original enrolled key. The service account needs access to that
specific Docker socket. Export refuses to overwrite existing credentials.

Set the packaged daemon configuration's `credentialFile` to this `identity.json`.
Use a separate private `stateDir` for the journal. Provision the reviewed
`execution` configuration for the desired Standard/Kata profile; the generic
`config.example.json` intentionally has execution disabled. Install the packaged
systemd unit and required sysusers/tmpfiles configuration, then start the daemon:

```sh
sudo systemctl start neticora-runnerd
sudo -u neticora-runnerd /usr/bin/runnerctl status
sudo -u neticora-runnerd /usr/bin/runnerctl doctor
sudo -u neticora-runnerd /usr/bin/runnerctl executions
```

Only enable the host through the authorized platform flow after qualification.
Trigger the dedicated trusted GitHub workflow using the pool's exclusive label.
Verify the provider-owned result, local execution state, physical cleanup,
durable CLEANED event, ACK and released platform reservation. Never use a Ready
UI label alone as evidence that a job ran or cleanup completed.

This archive supplies registration tooling and the existing execution binaries;
it does not automatically grant qualification or produce a ready-to-execute
configuration from the UI token alone.
