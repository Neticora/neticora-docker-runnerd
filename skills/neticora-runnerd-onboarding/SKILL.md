---
name: neticora-runnerd-onboarding
description: Work on Ubuntu Runnerd setup, pool-bound enrollment, signed connection recovery, or installed Standard execution activation. Use for host-side implementation, diagnostics, and verification of the Alpha integration.
---

# Neticora Runnerd onboarding

[Alpha PR #336](https://github.com/Neticora/neticora-alpha/pull/336) integrates
pool-bound enrollment and host lifecycle checks. Match the agent and deployed
Alpha revisions before interpreting protocol or database behavior.

- For onboarding, use [Ubuntu installation](../../docs/UBUNTU-INSTALLATION.md)
  and inspect `internal/onboarding`. Verify the HTTPS host API path, canonical
  tenant, and existing eligible pool. Diagnose Docker preflight under the
  dedicated service identity. Keep enrollment tokens at the masked prompt.
- For an interrupted setup, retain the original request, key, identity, and
  pool binding. Check if the first response committed before asking for a new
  token. Use the bounded same-token retry or signed same-pool replacement
  procedure in the installation guide as appropriate.
- For a reboot or endpoint change, use [connection recovery](../../docs/CONNECTION-RECOVERY.md).
  Check durable obligations before using the clean observation transition.
  A blocked recovery receipt is diagnostic. Keep it distinct from an accepted
  heartbeat, a fresh inventory snapshot, and a qualified execution session.
- For a connected host with no work, check qualification, local drain, signed
  handoff, platform admission and capacity separately. Use
  [activation](../../docs/EXECUTION-ACTIVATION.md) for the installed disk-backed
  Standard controller and [telemetry](../../docs/RESOURCE-TELEMETRY.md) for
  timestamped observations. Preserve cleanup and reservation obligations
  through recovery or retirement.
- For changes to contracts, run the repo's contract checks and the applicable
  cross-language tests in `neticora-alpha`. For live evidence, use the
  `neticora-k8s/infra/runnerd` lab runbook and record the exact installed
  package, agent, platform and Engine tuple. A setup smoke test verifies
  enrollment and observation. A real job and acknowledged cleanup verify
  execution.
