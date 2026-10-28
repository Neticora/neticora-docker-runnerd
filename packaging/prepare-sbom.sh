#!/usr/bin/env bash
set -euo pipefail
candidate=${1:?usage: prepare-sbom.sh CANDIDATE_DIRECTORY ABSOLUTE_NEW_OUTPUT_DIRECTORY}
output=${2:?New output directory required}
[[ "$output" = /* ]] || exit 2
mkdir -m 0700 "$output"
# Inspect actual Go binaries, not just opaque compressed distribution archives.
# Inputs are locally built candidates; this helper is not an untrusted installer.
for architecture in amd64 arm64; do
  mkdir -m 0700 "$output/$architecture"
  tar --no-same-owner --no-same-permissions -xzf "$candidate/runnerd-linux-$architecture.tar.gz" -C "$output/$architecture"
  test -f "$output/$architecture/bin/runnerd"
  test -f "$output/$architecture/bin/runnerctl"
  test -f "$output/$architecture/bin/runnerd-verify"
done
