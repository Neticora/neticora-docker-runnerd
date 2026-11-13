# Ubuntu installation and onboarding

This package continues the Runnerd08 Linux Standard implementation accepted at
`2a8c68145e5d`. Its target is **Ubuntu 26.04 LTS amd64**. A local engineering
package is unsigned and does not authorize production execution. Qualify the
exact installed package, kernel, Docker API/Engine and ext4 storage tuple before
admitting work; neither this document nor a successful heartbeat supplies that
qualification. Other Ubuntu versions and Kata execution are outside this package.

## Build and verify

Use the exact `toolchain` in `go.mod`, Git, Python 3 and `dpkg-deb`. Populate the Go
module cache through your trusted dependency process first. The build is offline,
requires a clean committed tree, and builds a private Git checkout containing
only committed source. It retains Go build information and records source/tree,
toolchain, dependency SBOM, package and executable SHA-256 digests.

```sh
make deb
cd dist/ubuntu-amd64/<version>
sha256sum -c SHA256SUMS
dpkg-deb --info neticora-runnerd_*.deb
dpkg-deb --contents neticora-runnerd_*.deb
```

`SOURCE_DATE_EPOCH` defaults to the source commit time. The same source/toolchain,
package version and timestamp should produce identical artifacts. For an explicit
version use `python3 packaging/build-deb.py --version <version>`. Output directories
must be new. The external manifest includes the final package digest; embedded
provenance intentionally excludes that digest to avoid circular hashing.

Transfer the package, manifest, SBOM and `SHA256SUMS` over an independently
authenticated channel. A matching checksum establishes equality to the expected
artifact, not the identity of its producer. There is no production signature,
public download or APT repository implied by this local build.

## Customer prerequisites

Provision Docker independently, with an explicit directly owned local dockerd Unix
socket and the accepted Runnerd08 endpoint model. The installer never installs,
reconfigures or restarts Docker, or changes networking. An administrator must
provide the service account its narrowly selected endpoint access under the
accepted Standard deployment model (for example a dedicated endpoint socket ACL).
The package does not add the account to `docker`, grant capabilities/sudo, change
socket permissions, or silently authorize arbitrary Docker endpoints. Standard's
accepted Docker access remains privileged runtime authority; this is not the
unfinished Runnerd09 controller/broker containment model.

Provide sufficient persistent ext4 storage and HTTPS connectivity to the host API.
The target does not need Go. No package configuration, credentials or identity are
generated on install; the unconfigured service remains stopped and disabled.

## Enroll

```sh
sudo apt install ./neticora-runnerd_<version>_amd64.deb
sudo neticora-runnerd setup
```

In Neticora Runner Hosts select the intended tenant and an existing customer-host
pool, then generate a single-use token valid for 15 minutes. Pool creation remains
in the existing pool workflow (#326); setup cannot create a pool. Copy the canonical
tenant ID and pool ID displayed by the dialog, and the HTTPS host API URL supplied
by your platform administrator. Enter the token at the hidden terminal prompt;
never put it in arguments, environment variables, shell history or logs.

Setup runs file, key, enrollment and Docker observations as the service account,
without supplementary groups. Root is used only to select that account and, after
explicit confirmation, start the installed systemd unit. It persists the original
Ed25519 key and request before sending the existing enrollment proof. Only the
token hash persists. If the response is lost, retry with that exact token within
the server's existing ten-minute response-recovery window. A recovered response
is authenticated through the existing proof-of-possession token exchange and the
new read-only `/me/installation` handoff. The verified tenant, pool, original key,
request, installation and session must all match before credentials are written.

Keep failed setup state. Never delete it to retry with another token or create a
replacement host. If the bounded server recovery window expires without a saved
response, contact the operator; setup deliberately fails closed. Once the response
is durable, retry does not need the enrollment secret. A partial credential/config
write resumes using the original identity. Existing legacy installations, changed
bindings, active daemons and histories without an original setup attempt are
rejected rather than overwritten or rebound.

The generated configuration uses the existing protected format and state paths:

- `/etc/neticora-runnerd/config.json`: atomic service-owned `0600` configuration.
- `/etc/neticora-runnerd/identity.json`: original protected credentials.
- `/etc/neticora-runnerd/setup/`: original key, token hash, request and response.
- `/var/lib/neticora-runnerd/`: unchanged SQLite journal and recovery records.
- `/var/lib/neticora-runnerd-keys/`: existing execution key state.

Connection mode reports zero execution capacity and no supported profiles. It
authenticates and sends heartbeats but cannot pull commands, create/start/remove
containers, acknowledge work or issue disposal evidence. Enrollment/connected,
independently qualified, and explicitly schedulable are separate states. Enabling
execution requires the existing reviewed local policy, capabilities and trust
provisioning plus independent platform admission; setup never supplies these.

## Inspect and recover

```sh
sudo neticora-runnerd status
sudo neticora-runnerd doctor
sudo runnerctl executions
sudo systemctl status neticora-runnerd
sudo journalctl -u neticora-runnerd
sudo dpkg --verify neticora-runnerd
```

Status and doctor redact keys/tokens and never repair, erase or rebind state.
Doctor checks protected configuration/credentials, original Docker endpoint and
the authenticated installation binding. Authentication creates only normal
short-lived access credentials, not a new identity/session or execution authority.
Use `dpkg --verify` and the externally authenticated build manifest for package
integrity; the package digest cannot be authenticated from inside the package.
Exit failure indicates a failed check; an offline status reports service unavailable
without opening/migrating SQLite. Setup and doctor do not clear journal locks.

Docker restart or host reboot changes the original endpoint identity. Preserve
the journal/credentials and use the existing Runnerd08 signed continuity-recovery
procedure. Connection/setup cannot treat a new boot, missing object or changed
socket as authority to discard history. Ordinary daemon stop preserves workloads
through `KillMode=process`; the original controller/journal perform recovery.

## Reinstall, replace and remove

Package scripts do not start/restart an installed daemon or modify configuration.
If it is running, replacement/removal is rejected. Explicitly drain using
`sudo runnerctl drain`, inspect pending execution/recovery obligations, and stop
the service before installing a compatible package. Do not stop Docker or remove
original workloads. Restart only through the existing supported recovery path.

The service-state check also rejects startup/shutdown/reload transitions, a live
main/control process and failed or incomplete systemd queries. Restore systemd
connectivity and establish a stopped service before retrying; a query error is
never evidence that replacement is safe. Unattended updates must not stop the
daemon automatically to bypass this check.

Reinstall, remove and even purge preserve the service account, original identity,
configuration, SQLite journal, cleanup records and recovery evidence. Package purge
is not decommissioning authorization. Destructive decommissioning requires separate
approval and independently verified safe disposal of every original obligation.

No arbitrary version pair is declared compatible. Record and test each exact pair,
including active-workload continuity and schema downgrade rejection, before use.
Historical Runnerd08 rollback and power-loss evidence retains its original build
identity and is not a new qualification of this Debian artifact.
