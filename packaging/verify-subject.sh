#!/usr/bin/env bash
set -euo pipefail
subject=${1:?usage: verify-subject.sh FILE_OR_DIGEST_PINNED_OCI_REFERENCE}
case "$subject" in
  oci://*)
    [[ "$subject" =~ @sha256:[a-f0-9]{64}$ ]] || { echo 'Image verification requires an immutable SHA-256 digest' >&2; exit 2; }
    ;;
  *) [[ -f "$subject" ]] || { echo 'Artifact file is required' >&2; exit 2; } ;;
esac
# A successful check establishes artifact origin only, never deployment readiness.
# Trust is scoped to the reviewed main-branch candidate workflow, never arbitrary
# signatures or a workflow chosen by the downloaded artifact itself.
gh attestation verify "$subject" \
  --repo Neticora/neticora-docker-runnerd \
  --signer-workflow Neticora/neticora-docker-runnerd/.github/workflows/release-candidate.yml \
  --source-ref refs/heads/main \
  --deny-self-hosted-runners
