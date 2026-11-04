# Neticora Runnerd

Neticora Runnerd is an open-source runner-management agent being developed for
customers who want to run CI workloads on infrastructure they control.

Runnerd is designed to connect customer-managed hosts to Neticora and manage the
local lifecycle of ephemeral CI runners, while keeping execution subject to
customer-defined policy.

## Project status

Runnerd is under active development. This repository currently contains the
versioned host protocol, Go SDK, and a development Linux service/CLI foundation.
The service reports local status and remains unavailable for job admission.
An offline verification foundation checks signed update artifacts against
independently provisioned trust. Production installation and runner execution are
not yet supported.

The presence of protocol definitions does not imply support for a particular
operating system, container runtime or isolation profile.

## Feedback and contributions

Use [GitHub Issues](https://github.com/Neticora/neticora-docker-runnerd/issues)
for bug reports, feature requests and general feedback. Discuss substantial
changes with maintainers before opening a pull request.

Do not include credentials, access tokens or private infrastructure details in
public issues or pull requests.

The `identity` SDK constructs Ed25519 enrollment, short-lived assertion and
rotation proofs without storing private keys. `identity.NarrowPolicy` intersects
server configuration with locally provisioned ceilings. `transport.Client.Config`
retrieves strictly validated configuration; enrollment/token requests can omit a
bearer credential. These helpers do not wire daemon enrollment, durable identity
storage or execution. Persist request IDs/keys securely before enrollment or
rotation; retain old/new keys until rotation response recovery is durable.

## Live gateway follow-up qualification

Live qualification is Linux-only and must use a new, disposable host created by
`TestLiveGatewayEnrollment`. It is not a daemon lifecycle or runtime test.

Before initial enrollment, set `RUNNERD04_EXPECTED_TENANT_ID` to the canonical
internal tenant ID returned by the authenticated management API, in addition to
`RUNNERD04_LIVE_ENDPOINT`, `RUNNERD04_ENROLLMENT_TOKEN_FILE` and a new
`RUNNERD04_LIVE_STATE_DIR`. After successful enrollment and admission-disabled
config checks, the test creates `disposable-host.json`, binding its purpose,
endpoint, tenant, new host ID and enrollment request ID. Do not manufacture a
marker for an existing host; older test state without this marker is rejected.

Every follow-up requires these separate operator inputs:

```bash
export RUNNERD04_ALLOW_DESTRUCTIVE=true
export RUNNERD04_EXPECTED_HOST_ID='<new disposable host ID from enrollment>'
export RUNNERD04_EXPECTED_TENANT_ID='<canonical internal tenant ID>'
export RUNNERD04_ADMIN_HEADER_FILE='<absolute protected Authorization-header file>'
```

The guard compares expected IDs with the enrollment marker/state, then uses the
real administrator API to independently confirm the tenant and host. It refuses
anything except an unassigned `PENDING` host with admission explicitly disabled.
Only a read-only management GET may occur before these checks pass. Rotation,
revocation, deliberate rate exhaustion and controlled deadline probes all use the
same guard; missing or inconsistent inputs fail closed before mutating requests.
Administrator headers and enrollment token files must be owner-controlled regular
files with no group/other permissions. Refresh short-lived administrator sessions
before each separate test; do not print their values.

Identity directories must be owned by the executing user with mode 0700. Files
must be private regular files, normally 0600. Unsafe ownership/permissions,
symlinks and writable/untrusted ancestors are rejected rather than repaired.
Writes use random exclusive temporary files, file/directory sync and atomic
replacement. An advisory identity lock prevents concurrent qualification runs.

Run explicit test names, not the entire live suite on one reused identity:

1. Choose **one** rotation scenario per newly enrolled host:
   - `go test -count=1 -v ./transport -run '^TestLiveGatewayHeartbeatRotation$'`
     checks config/ETag, synthetic zero-capacity heartbeat, stale epoch rejection,
     ordinary rotation, duplicate-response recovery and old-key/token fencing.
   - Alternatively set `RUNNERD04_LOSE_ROTATION_RESPONSE=true` and run
     `go test -count=1 -v ./transport -run '^TestLiveGatewayLostRotationResponse$'`.
     The transport drains/discards the first successful rotation response before
     delivering it to the caller. A fresh request is reconstructed from the
     protected `rotation-attempt.json` and original key file, retaining the same
     request ID and both signing keys. No first-response identity is used.
     This proves a lost HTTP response, not process-restart recovery: the old
     unexpired access token stays in memory only. The API's bounded recovery
     period still applies; a lost process/session may need administrative recovery.
   Both scenarios persist the new seed/identity atomically to `rotated-state.json`
   and refuse to replace an existing completed or uncertain rotation attempt.
2. `go test -count=1 -v ./transport -run '^TestLiveGatewayBodyAndHostLimits$'`
   checks malformed/oversized/compressed input, waits 61 seconds without host
   requests for a new window, then requires exactly 120 accepted reads and five
   structured 429s. The probe must finish inside one window and its anonymous
   control must still get the expected schema-error 400, excluding an already
   exhausted global/anonymous budget. Concurrent traffic on the test host makes
   the test fail; it is not silently accepted as evidence of host throttling.
3. `TestLiveGatewayDeadline` also requires `RUNNERD04_CONTROLLED_DEADLINE=true`.
   After client readiness, the operator holds a row lock on only the verified
   disposable host and creates `deadline-lock-ready` privately in its state
   directory. Hold the lock until the 8s structured timeout is observed, then roll
   back. Remove stale marker files before a new probe. Do not modify handlers or
   database authority to fabricate results. Wait for a consumed host-rate window
   to expire before this separate test.
4. `go test -count=1 -v ./transport -run '^TestLiveGatewayRevocation$'` checks
   management scope, metadata secrecy and enrollment/key/host revocation. All
   management paths use the canonical expected tenant ID. It permanently retires
   this disposable identity; no later positive authentication test can reuse it.

Verify administrative audit evidence separately. Retain uncertain recovery state
until resolved; remove credential/state files only after final revocation. Local
mock/safety tests do not establish live acceptance. Previously recorded live
results predate these stronger guards; rerun them on a new disposable host before
claiming qualification of this revised harness.

### Runnerd05 bootstrap recovery transport

The additive `CustomerManagedPolicy` wire schema is explicitly version 1.1 and
assigns host networking to the customer. Legacy CustomerPolicy 1.0 retains its
published semantics. Both retain signature trust, tenant/pool/profile/resource
limits, credential/interface isolation, TLS, freshness and replay protections.
This schema addition does not implement local daemon admission or runtime policy.

Runnerd05 `/start` requests include an independent X25519 `bootstrapPublicKey`.
Persist its protected private key and startRequestId before requesting bootstrap;
never substitute the Ed25519 enrollment key or write private keys/bootstrap into
command/event/journal payloads. `transport.OpenBootstrap` validates/decrypts the
`runnerd05-sealed-v1` response against exact tenant/host/execution/generation,
startRequestId/spec and expiry. It is a transport helper, not launch authority.
The caller must recheck current signed command, local non-network policy, image
trust and cancellation before execution. Erase plaintext immediately after use.

The envelope derives AES-256-GCM from ephemeral X25519 via HKDF-SHA256. Its salt is
SHA256 of canonical context (all envelope fields except nonce/ciphertext), info is
`neticora-runnerd-bootstrap-v1`, nonce is 12 bytes and the 16-byte tag follows the
ciphertext. Outer encoding is base64url canonical JSON. The context includes both
recipient/ephemeral public keys and immutable start identity; delivery expires by
the provider/bootstrap deadline independently of bearer renewal. Cross-language
public fixtures exercise TypeScript sealing and Go decryption with binding,
expiry, duplicate-key and ciphertext rejection.

The SaaS owns placement, issuance uncertainty, provider identity and physical
reservation decisions. These helpers add no SQLite/Docker execution controller;
process persistence, automatic fenced local recovery and live runtime admission
remain separate milestones. See Alpha's `docs/runnerd/RUNNERD05-DISPATCH.md`.

# Runnerd05 creation fence

The repository declares Go 1.26 and pins the Go 1.27.3 toolchain. Contract CI
installs Go 1.27.3 with `GOTOOLCHAIN=local`; its root-module compile, race tests and
build include both `journal` and `transport`. This supports `crypto/hkdf` and
`os.Root`; Go 1.23 is below the repository's supported version.

`journal.Open` requires a protected pre-provisioned directory. An executor must
call `ClaimCreation` and durably commit its exclusive marker before **any** Docker
create for a start command. `FenceNeverStarted` writes a permanent tombstone and
signs a scoped proof only when no creation marker exists. A crashed or uncertain
creation claim cannot produce absence evidence; do not delete or compact markers.
The platform also requires fresh complete inventory and independent qualification
of this journal boundary. This library does not yet wire the daemon to Docker or
provide autonomous recovery.
