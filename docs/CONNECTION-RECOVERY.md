# Connection-only reboot recovery

An enrolled observation-only installation retains its installation ID, tenant,
pool and original Ed25519 key across reboot. A new boot or authenticated Docker
endpoint never silently becomes execution authority. Normal startup runs the
read-only observer and waits for an explicitly approved observation transition.

## Operator workflow

Complete setup and answer **yes** to “Start Runnerd now and enable startup on
boot?”. Package installation alone never starts or enables an unenrolled agent.
For an already enrolled installation, run:

```sh
sudo neticora-runnerd enable-startup
sudo systemctl start neticora-runnerd
sudo neticora-runnerd status
```

Startup is independent of execution qualification. `enable-startup` validates the
protected enrolled configuration and only enables the systemd unit; it does not
start it, change Docker access, or grant execution authority. Both configuration
and enrollment credentials must exist for the shipped unit to start.

After boot/endpoint change, status reports `connection-resynchronization-blocked`,
the exact `connectionRecoveryOperationId` and reason. A tenant superuser or platform
administrator reviews the pending transition through the normal authenticated API:

```text
GET /api/v1/tenants/{tenantId}/runner-hosts/{hostId}/connection-resync
POST /api/v1/tenants/{tenantId}/runner-hosts/{hostId}/connection-resync/{operationId}/approve
{"requestHash":"<the exact listed payloadHash>","reason":"Reviewed observation-only reboot"}
```

Review the installation/key fingerprint, old/new boot and endpoint, and journal
identity. Approval expires in fifteen minutes; an administrator can renew the same
operation. The service polls automatically and requires no new enrollment token.
Approval is an audited existing tenant-administration action, not a qualification
signature or a new signing authority. No live qualification signer is involved.
A reboot will wait for this approval; startup enablement does not preapprove a
future boot. Existing general administrative resynchronization and signed execution
peer recovery retain their original meaning and are not bypassed by this flow.

## Safety boundary

The narrow path requires an intact original journal with no execution history,
commands, reservations, storage ownership or existing signed recovery records, and
no established execution scope. Historical execution installations use the signed
execution peer-recovery procedure, even when they appear idle. Missing/corrupt
journal evidence, unknown installation-labeled Docker objects, outstanding platform
resources/commands/operations, held capacity or an obsolete source session block.
Unrelated customer Docker objects are outside installation-owned inventory; no
universal trusted-host reference claim is made.

Both approval and commit use the same platform obligation verifier under the host
row lock. Commit rechecks all conditions and active original enrollment/pool/key
bindings. It advances the session once, revokes old access tokens, clears previous
qualification/capacity and inventory freshness, and keeps the host pending with
admission disabled. It never changes execution reservations or creates a command.
Inventory generation is preserved and the ordinary accepted-generation protocol
continues. Fresh inventory and metrics remain separate from qualification.

The original credential file is immutable. A protected journal operation and
`connection-binding.json` in the state directory hold the accepted observation
binding. Only connection-only code and read-only diagnostics use that overlay;
execution startup continues to require its original signed continuity procedure
and authoritative execution checkpoint. Systemd needs no writable `/etc` exception.

## Persistence and recovery

Before HTTP, SQLite persists one random operation ID, canonical request/hash and
original journal identity/revision through the normal WAL + anchor mechanism.
Fresh purpose-scoped Ed25519 proofs authenticate that same operation on retries;
short-lived proof nonces cannot be replayed as ordinary session assertions.
The platform stores the immutable request in an existing operation row, records
administrative approval through existing claim/state fields, and commits the new
binding and terminal operation atomically. A committed response is deterministic.

After receiving the exact committed response, the agent re-observes Docker,
persists the receipt, atomically fsyncs the observation overlay, then records local
completion. Failure at any step retains the same operation. Response loss uses a
fresh signed proof to recover that original result. A lagging local anchor can be
recovered only for its exact known connection operation after authenticated server
confirmation; this never establishes execution readiness. A newer boot/endpoint
during an unfinished operation blocks rather than allocating a replacement.
Concurrent processes remain excluded by the existing installation lock.

Connection recovery never starts, adopts, stops or removes a Docker resource,
ACKs work, releases a reservation, reconciles execution scope, or enables admission.
Do not remove enrollment, journal, anchor, pending operation or overlay files to
bypass a blocked transition. Preserve evidence and use administrative recovery.

The local schema adds `connection_resync` (version 5). Older binaries intentionally
reject the newer schema; package rollback requires an independently reviewed state
compatibility procedure, not deletion or downgrading of the journal.
