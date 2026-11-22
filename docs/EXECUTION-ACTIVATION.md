# Installed Standard execution activation

This procedure consumes separately reviewed policy, capabilities, image trust and
operator-signed acceptance. It never creates acceptance or changes platform
admission. Target: the installed Ubuntu amd64 disk-backed Standard controller;
Docker builds and hard aggregate storage guarantees remain disabled.

For the Alpha integration from PR #336, provider binding, independently
signed qualification staging, signed initial execution handoff, local
activation with current inventory, and explicit platform admission each
require their own evidence. Confirm the matching platform path is deployed
before starting this procedure. Preserve the original enrollment identity
and journal across the handoff. [Alpha integration sequence](https://github.com/Neticora/neticora-alpha/blob/a1376d7a0f894117b8907ee57ec5df70f5faf166/docs/runnerd/ALPHA-INTEGRATION.md#advance-a-reviewed-host-to-execution)

## Required inputs

Retain the original setup credentials, connection binding, journal and anchor.
Run connection mode at least once to initialize that original journal. Provision
the execution directories, local policy, capabilities and offline image trust
using the existing execution preparation contract. Do not copy a lab identity.

Add these fields to a complete inactive candidate execution configuration:

```json
{
  "qualificationFile": "/etc/neticora-runnerd/qualification.json",
  "qualificationPublicKeyFile": "/etc/neticora-runnerd/qualification-public.pem",
  "runnerSize": "small",
  "enabled": false
}
```

These are fields inside `execution`, alongside its existing required fields.
Files must be service-owned, private and outside journal, workspace and bootstrap
directories. Provision the public verifier key independently; never trust a key
supplied by the acceptance artifact itself. The same Ed25519 manifest/signature
envelope is used by platform dispatch. It must identify this installed agent
version, tenant, host, session, Docker endpoint, exact policy and capabilities,
and a `linux-github-disk-v1` spec for `runnerSize`. Image/provider references,
artifact expiration and offline trust freshness remain mandatory. Historical
Runnerd08 acceptance does not qualify this source or disk-backed template.

## Explicit two-stage transition

1. Run `sudo neticora-runnerd prepare-execution /etc/neticora-runnerd/candidate.json`.
2. Explicitly drain and stop the daemon. Activation refuses an installation whose
   instance lock is held, unresolved local work, unknown platform executions,
   incomplete original journal, changed identity, boot or Docker binding.
3. Run `sudo neticora-runnerd activate-execution /etc/neticora-runnerd/candidate.json`.
   This authenticates the installation, verifies independent acceptance and
   existing image trust, then atomically installs the execution configuration.
   A durable local drain is committed first. No workload starts.
4. Start the daemon explicitly. It reconciles the original journal and publishes
   qualified capabilities and inventory while locally drained. This permits the
   independent operator to approve the exact observed tuple through the existing
   platform qualification/admission workflow. A successful heartbeat grants none
   of that authority.
5. After explicit platform admission, stop the idle daemon again and run
   `sudo neticora-runnerd resume-execution`. Resume repeats the checks, requires
   current authenticated remote admission and policy ceilings, and only then
   removes the local drain. Start the service explicitly afterward.

Activation never changes customer networking, starts/restarts Docker, enrolls
again, clears history or manufactures qualification. Interrupted activation is
retryable with the same candidate. Once installed, only an identical candidate
can resume. Existing active histories use their original recovery procedure.
Explicitly drain/stop before changing execution configuration or package version.

Qualification expires independently of service health. The controller rechecks
it for each new start; expiration does not disable receipt replay, event reporting
or cleanup. Normal start gates still revalidate remote authority and transport.

## Diagnostics

`runnerctl status` exposes `runtimeQualified`, `qualificationState`,
`platformAdmissionEnabled`, and `dispatchBlockers`. Runtime qualification means
current independent signed acceptance; admission also requires fresh platform
observation, reconciled journal and no local drain. Stale observations, missing
acceptance, storage quarantine and recovery failures produce separate blockers.
These fields are diagnostics, never authority for a launch.

## Acceptance evidence

The shipping package and actual real GitHub workflow require separate execution
on an approved host. Source tests cannot establish physical runtime behavior.
Use Alpha's `installed-execution-evidence.cjs` together with the infrastructure
`collect-installed-execution.py` collector. Preserve the exact package manifest,
installed binary hash, Ubuntu/systemd/Docker/kernel/filesystem tuple and source
revision. Independently collect provider assignment/result, management pool audit,
webhook, placement, command and JIT issuance, platform event preimages, native
event hashes/ACKs and final physical absence.

Resource and recovery witnesses must name this package/binary and host. Required
cases include CPU, memory, PIDs, disk lifecycle, network, concurrency, duration,
cancellation, lost start response, agent restart, Docker restart, reboot and
interrupted cleanup. Existing guarded fault tools require their original lab
authorization; no fault action is performed by activation or evidence verification.
No image build is required to develop or run the offline verifiers. A real
campaign uses an independently accepted existing image digest.
