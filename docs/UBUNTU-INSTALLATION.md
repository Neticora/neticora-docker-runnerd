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

Provision Docker independently, using a local root-owned Linux Docker Engine Unix
socket. Both a directly bound socket and Ubuntu's standard `docker.socket` with
`dockerd -H fd://` are supported; keep the vendor Docker units and flags. The installer never installs,
reconfigures or restarts Docker, or changes networking. Setup can authorize the
dedicated service account through the host's standard Docker group, only after
explicit administrator approval.
The package does not add the account to `docker`, grant capabilities/sudo, change
socket permissions, or silently authorize arbitrary Docker endpoints. Standard's
accepted Docker access remains privileged runtime authority; this is not the
unfinished Runnerd09 controller/broker containment model.

The normal Ubuntu onboarding flow is:

```sh
sudo apt install ./neticora-runnerd_*_amd64.deb
sudo neticora-runnerd setup
```

Setup resolves the dedicated account's primary and supplementary groups from
the operating system identity database, initializes exactly those groups before
dropping privileges, and verifies the resulting identity. It never inherits root's
groups or performs enrollment/Docker probes as root. Existing authorized Docker
group membership works immediately; no new login or socket ACL is needed.

If the service account cannot access a standard root:docker socket with mode
0660, setup explains Docker's root-equivalent access and offers:

```text
[1] Authorize and continue
[2] Cancel
Selection [2]:
```

Only selection `1` authorizes adding `neticora-runnerd` to the Docker group. The
root parent uses fixed argument-based account management, reinitializes the
service identity in a fresh nonroot child, and continues with the same public
setup answers and original enrollment state. The invoking human is not added.
Declining, invalid input or authorization failure leaves enrollment intact and
does not prompt for or consume a token. No manual permission commands are needed.

The package installer does not grant Docker access. Setup never changes socket
ownership, mode or ACLs, Docker units/flags/configuration, or restarts Docker.
Nonstandard sockets require administrator review rather than automatic rewriting.
Group membership persists when Docker recreates its standard socket; this does
not approve a new daemon identity or discard the existing continuity binding.
Rootless/remote engines and arbitrary socket proxies remain unsupported.

The connection authenticates the actual root `dockerd` process, not PID 1. For
systemd activation, a bounded credential-free `HEAD /_ping` receives Linux
`SCM_CREDENTIALS` on the same Unix connection before it can carry a mutation.
Replies must retain that sender; daemon PID/start time and host boot identity
remain part of the original continuity binding. No Docker service restart or
unit/configuration change is needed for normal onboarding.

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
by your platform administrator. Enter or paste the token at the terminal prompt;
each character appears as `*`. Press Enter to submit, Backspace to correct the
entry, or Ctrl+U to clear it. Never put tokens in arguments, environment variables,
shell history or logs.

Setup runs file, key, enrollment and Docker observations as the service account,
without supplementary groups. Root is used only to select that account and, after
explicit confirmation, start the installed systemd unit. It persists the original
Ed25519 key and request before sending the existing enrollment proof. Only the
token hash persists. If the response is lost, retry with that exact token within
the server's existing ten-minute response-recovery window. A recovered response
is authenticated through the existing proof-of-possession token exchange and the
new read-only `/me/installation` handoff. The verified tenant, pool, original key,
request, installation and session must all match before credentials are written.

Preflight distinguishes missing/inaccessible sockets, denied service-account
permissions, unavailable daemons, unsupported configurations and continuity
failures. Failed preflight does not prompt for or consume a token, create a new
key/attempt, or change an existing one. Docker is checked again immediately
before enrollment submission and before credential/configuration commit. If
Docker changes after the platform commits, the original saved response is
retained for recovery; a retry must not create a replacement identity.

Diagnostics use `DOCKER_ACCESS_NOT_AUTHORIZED`,
`DOCKER_GROUP_MEMBERSHIP_INACTIVE`, `DOCKER_AUTHORIZATION_FAILED`,
`DOCKER_SOCKET_UNAVAILABLE`, `DOCKER_DAEMON_UNAVAILABLE`,
`DOCKER_ENDPOINT_UNSUPPORTED` and `DOCKER_CONTINUITY_CHANGED` to distinguish
operator actions. Group mismatch fails closed; rerunning setup with sudo creates
a fresh service-identity process. Systemd's `User=neticora-runnerd` and
`Group=neticora-runnerd` initialize the same configured supplementary groups when
starting the installed service. Setup does not restart a running Runnerd daemon;
an active installation retains its lock and original recovery obligations. Any
required Runnerd restart must follow the existing safe lifecycle procedure.

Keep failed setup state. Never delete it to retry with another token or create a
replacement host. If the original token expired or is unavailable before enrollment
completed, create a fresh token for the **same tenant and pool**, then run:

```sh
sudo neticora-runnerd setup --replace-token
```

Accept the saved bindings and paste the fresh token. Replacement requires an
upgraded platform. Setup signs the full recorded candidate history except the
token being redeemed, including later failed attempts after a lost response.
The original token is first whenever it is a predecessor. The platform locks
the current token and all known candidates,
checks that the original never registered a host and the original request was
never consumed by another replacement, and atomically revokes all known unused
same-scope predecessors while registering the fresh token. The original anchor
must exist. Non-original hashes that never existed can be ignored as typos;
known consumed, inconsistent or cross-scope candidates reject replacement.
The original key, request and attempt remain
unchanged; append-only local records retain token hashes, never token values.
An interrupted replacement resumes with ordinary `setup` and the same fresh token.
If a candidate was mistyped or expired without registration, explicit replacement
can accept another fresh token. Earlier candidates remain in local history; a
successful earlier registration always blocks a second host for the same request.
Bounded response recovery may supply a signed extension of the original history
to retire omitted unused candidates. It must match the original identity, key,
request and an exact earlier history prefix, and cannot change the original
request hash or deadline. The registered original token itself is the anchor
when recovering an original non-replacement request.
At most 16 replacements are retained; reaching this bound requires operator recovery.

Replacement is rejected if local credentials, an enrollment response or runtime
history already exists, or the platform reports a consumed/uncertain original or
changed tenant/pool. A lost successful response must recover the original host
with its saved token; it cannot authorize another host. If that response-recovery
window expires, contact the operator; setup fails closed. Once the response
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

Socket-path replacement and daemon restart are distinct observations. A different
socket inode invalidates the current observation even when the same authenticated
daemon process remains alive. A fresh read-only observation may then report the
same daemon endpoint identity; this does not itself authorize execution or
disposal. Existing event-stream invalidation and reconciliation rules still apply.

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

If APT/dpkg is interrupted, preserve all files, journals and the service account.
Record `dpkg --audit` and
`dpkg-query -W -f='${Status} ${Version}\n' neticora-runnerd` before changing anything.
Restore systemd connectivity and verify a stopped service with no main/control
process. For an already unpacked compatible candidate, use
`sudo dpkg --configure neticora-runnerd`. For an interrupted unpack or a missing
payload, reinstall the exact independently verified compatible `.deb`, then
configure that package. Inspect its manifest, installed executable digest and
original recovery obligations before an explicit restart. Do not repair by
deleting package locks, replacing dpkg's database, clearing Runnerd state or
forcing a downgrade. Investigate any live package-manager process first.

Unattended updates must honor the stopped-service refusal. An APT failure is not
permission to stop a job, discard state or release its reservation. Arrange a
reviewed maintenance window and retry only after the normal drain/recovery checks.
Local noninteractive APT tests do not qualify every unattended-update service,
arbitrary binary/schema transitions, signed distribution or fleet rollout.

### Connection-only inventory and reported hostname

An enrolled connection-only service observes Docker and publishes complete,
authenticated inventory every 15 seconds, independently of the execution
controller. It still advertises zero qualified capacity, no execution profiles,
and disabled admission. A heartbeat is not an inventory receipt or qualification.
`status` and `doctor` expose `inventoryState`, `inventoryGeneration`,
`inventoryObservedAt`, and `inventoryFresh` separately from platform connectivity.
Inventory expires after 60 seconds without an accepted fresh observation.

This mode publishes only when the original endpoint remains bound and local
incomplete executions, platform recovery obligations, and installation-scoped
Docker resources are all empty. Any resource needing ownership reconciliation
blocks publication; it is never adopted, removed or silently omitted. Diagnose
`unreconciled-*-resources` through the existing recovery workflow. Do not clear
state or enable execution just to obtain an inventory report. A Docker peer
change requires the existing separately authorized continuity recovery.

Inventory generations come from the authenticated platform recovery receipt.
An ambiguous response retains the exact observation for idempotent replay;
conflicts cause a new read and observation on the next interval. After a process
restart the observer resumes from the server's accepted generation. Observation
retries do not create execution authority or reconcile the local journal.

The OS hostname is included as display metadata in each new inventory snapshot.
Valid ASCII hostname/FQDN labels are bounded to 63 characters per label and 253
overall. An unavailable/invalid hostname is reported as null. A hostname change
needs no re-enrollment; the UUID and installation/key/session bindings remain the
security identity. Older agents may omit the optional field. Deploy the updated
inventory gateway protocol before installing this agent; older strict gateways
reject the new hostname field. No schema/database migration is required.
