#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: verify-subject.sh FILE_OR_DIGEST_PINNED_OCI_REFERENCE REVIEWED_SOURCE_SHA' >&2; exit 2; }
subject=$1
source_sha=$2
[[ "$source_sha" =~ ^[a-f0-9]{40}$ ]] || { echo 'A reviewed immutable source SHA is required' >&2; exit 2; }
case "$subject" in
  oci://*)
    [[ "$subject" =~ @sha256:[a-f0-9]{64}$ ]] || { echo 'Image verification requires an immutable SHA-256 digest' >&2; exit 2; }
    ;;
  *) [[ -f "$subject" ]] || { echo 'Artifact file is required' >&2; exit 2; } ;;
esac
# A successful check establishes artifact origin only, never deployment readiness.
# Trust is scoped to the reviewed main-branch candidate workflow, never arbitrary
# signatures or a workflow chosen by the downloaded artifact itself.
gh attestation verify \
  --hostname github.com \
  --repo Neticora/neticora-docker-runnerd \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --signer-workflow Neticora/neticora-docker-runnerd/.github/workflows/release-candidate.yml \
  --signer-digest "$source_sha" \
  --source-ref refs/heads/main \
  --source-digest "$source_sha" \
  --deny-self-hosted-runners \
  -- "$subject"
