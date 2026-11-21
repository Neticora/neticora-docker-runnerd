# Connection-only reboot recovery

Customers enroll once and enable startup. Ordinary reboots automatically restore
monitoring using the original installation ID, tenant, pool and Ed25519 key.
No administrator approval is required for a verified clean connection-only reboot.
Execution and genuine execution-recovery authorization remain separate.

## Startup

Complete setup and answer **yes** to “Start Runnerd now and enable startup on
boot?”. Package installation alone never starts or enables an unenrolled agent.
For an already enrolled installation:

```sh
sudo neticora-runnerd enable-startup
sudo systemctl start neticora-runnerd
sudo neticora-runnerd status
```

Startup is independent of qualification. `enable-startup` validates the protected
enrolled configuration and enables the unit; it does not start it, grant Docker
access or enable execution. If setup has never started the service, its empty
journal may be initialized on the original enrollment boot only. Missing journal
evidence after a boot change cannot be replaced by a fresh store. Both configuration
and enrollment credentials must exist for the shipped unit to start.

## Automatic observation transition

The observer authenticates the current Docker daemon and verifies the original
journal. This narrow path requires zero unresolved local executions, unacknowledged events,
reservations, cleanup/storage ownership or signed recovery obligations, and no
installation-labeled Docker objects. Completed immutable execution, command,
cleanup and disposal history is retained and does not block ordinary recovery.
Historical scope is checked against the original installation and retained unchanged.

The platform independently checks the original key/enrollment/pool binding,
source session/boot/endpoint and all execution, command, recovery, inventory and
reservation obligations under the host row lock. Admission must remain disabled. Recorded qualification, capacity and profiles
are preserved; an old qualification is unusable on the new session/endpoint under
the existing verifier. Recovery does not qualify or promote those records. A never-reported
host may use its original-key-attested source endpoint only if it has no recorded
inventory, qualification or capacity. Unknown or unresolved facts fail closed.

When both boot and authenticated Docker endpoint change consistently and all
checks pass, the platform atomically commits the one immutable operation and
advances the observation session exactly once. Old tokens and ordinary assertions
for the old session are fenced. Heartbeats, hostname, continuous read-only inventory
and telemetry resume. Inventory generation advances through the existing accepted
generation protocol. State, qualification, capabilities/profiles, capacity,
reservations, admission and execution recovery readiness are not promoted or
rewritten by the transition. Fresh monitoring does not establish qualification.

## Exceptional cases

A same-boot Docker endpoint change or inconsistent boot/endpoint tuple does not
use the normal reboot policy. For an otherwise verified empty installation, status
shows `connection-resynchronization-blocked`, the exact operation ID and reason.
A tenant superuser or platform administrator may review and approve that exact
exception through the existing authenticated management API:

```text
GET /api/v1/tenants/{tenantId}/runner-hosts/{hostId}/connection-resync
POST /api/v1/tenants/{tenantId}/runner-hosts/{hostId}/connection-resync/{operationId}/approve
{"requestHash":"<the exact listed payloadHash>","reason":"Reviewed exceptional empty endpoint transition"}
```

Approval expires after fifteen minutes and may be renewed for the same operation.
Approval cannot override unknown resources or unresolved obligations. Such cases remain fenced for operator investigation and
the existing genuine execution-recovery authorization process. No new signing
authority or live qualification signer is introduced.

## Restricted recovery observations

A blocked connection may POST a fresh original-key signature to
`/api/v1/runner-hosts/connection-status`. It uses the separate
`neticora-runnerd-restricted-status-v1` purpose, not session authentication. The
bounded proof contains installation/key binding, a diagnostic claimed epoch,
observed boot/endpoint, operation ID and reason. It returns a diagnostic receipt
only. No access token, command, cleanup permission, inventory acceptance or
reservation-release authority exists on this channel.

The platform verifies the active original key and tenant/enrollment/pool binding,
fresh timestamp and one-use nonce. The reported epoch is diagnostic context; an
older value never becomes an accepted execution session. Future epochs reject.
Only the latest `connectionRecoveryObservation` JSON column and short-lived replay
record change. Heartbeat `lastSeenAt`, session/boot/endpoint, inventory, telemetry,
qualification, capacity and admission stay unchanged. Exact timestamp replays do
not refresh the measurement receipt. The tenant-authenticated host API exposes
these observations with observed/received timestamps and an explicit
`executionSessionAccepted:false` marker. Interpret them as timestamped reports,
not current readiness or a substitute for normal heartbeat connectivity.

Reporting can run without opening or repairing a damaged journal. If the original
key/configuration is unavailable or revoked, or the platform is offline, only local
diagnostics are possible; there is no unauthenticated fallback. The nullable
platform diagnostic-column migration is required before deploying that endpoint.

## Durable recovery

Before HTTP, SQLite persists one random operation ID, canonical request/hash and
original journal identity/revision through the normal WAL and anchor mechanism.
Fresh purpose-scoped Ed25519 proofs authenticate the same operation on retries.
The platform stores the immutable request and commits the binding and terminal
operation atomically. The committed response is deterministic. Repeated and
concurrent requests cannot advance the session twice or silently accept old
ordinary assertions.

The original credential file remains immutable. After authenticated acceptance,
the observer rechecks Docker, persists the receipt, atomically fsyncs
`connection-binding.json`, then records completion. Failures retain the exact
operation. A newer boot during an unfinished ambiguous operation blocks rather
than allocating replacement authority. A lagging anchor is repaired only for its
exact known transition after authenticated server confirmation; execution readiness
is never established. The original installation lock excludes concurrent processes.

Only connection-only code and diagnostics use the observation overlay. Execution
startup still requires its original signed continuity procedure and authoritative
checkpoint. No writable `/etc` systemd exception is needed. Recovery never starts,
adopts, stops or removes Docker resources, ACKs work, releases reservations, or
reconciles execution scope. Preserve original evidence when blocked.

Local journal schema version 5 adds `connection_resync`. Older binaries reject it;
rollback requires reviewed state compatibility, never deletion or journal downgrade.
