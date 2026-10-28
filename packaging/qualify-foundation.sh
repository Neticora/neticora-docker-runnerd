#!/usr/bin/env bash
set -euo pipefail
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
output=${1:?usage: qualify-foundation.sh ABSOLUTE_NEW_OUTPUT_DIRECTORY ABSOLUTE_SYFT_BINARY}
syft_binary=${2:?Checksum-verified Syft binary required}
[[ "$output" = /* && "$syft_binary" = /* && -x "$syft_binary" ]] || exit 2
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || exit 2
# Qualification provenance must name an actual immutable local source snapshot.
# For pending work use a disposable Git snapshot, never invent a public revision.
[[ -z $(git status --porcelain --untracked-files=all) ]] || { echo 'A clean source snapshot is required.' >&2; exit 1; }
source_sha=$(git rev-parse HEAD)
mkdir -m 0700 "$output"
mkdir -m 0700 "$output/input"
bash packaging/build-candidate.sh "$output/input"
bash packaging/prepare-sbom.sh "$output/input" "$output/sbom-input"
SYFT_CHECK_FOR_APP_UPDATE=false SYFT_GOLANG_SEARCH_REMOTE_LICENSES=false \
  "$syft_binary" scan "dir:$output/sbom-input" -o "spdx-json=$output/input/sbom.spdx.json"
(cd "$output/input" && sha256sum ./*.tar.gz ./sbom.spdx.json > SHA256SUMS)
RUNNERD_QUALIFICATION_INPUT="$output/input" RUNNERD_QUALIFICATION_OUTPUT="$output/evidence" \
RUNNERD_QUALIFICATION_SOURCE="$source_sha" \
RUNNERD_QUALIFICATION_VERIFIER="$output/sbom-input/amd64/bin/runnerd-verify" \
  go test -mod=readonly -race -count=1 -tags runnerd_qualification -run '^TestBuiltCandidateQualification$' -v ./internal/updatetrust
