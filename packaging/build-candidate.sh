#!/usr/bin/env bash
set -euo pipefail
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
output_dir=${1:?usage: build-candidate.sh ABSOLUTE_OUTPUT_DIRECTORY}
[[ "$output_dir" = /* ]] || { echo 'Output directory must be absolute' >&2; exit 2; }
mkdir -p "$output_dir"
source_epoch=$(git show -s --format=%ct HEAD)
for architecture in amd64 arm64; do
  stage=$(mktemp -d)
  trap 'rm -rf -- "$stage"' EXIT
  mkdir -p "$stage/bin" "$stage/packaging"
  GOOS=linux GOARCH="$architecture" CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=true -o "$stage/bin/" ./cmd/...
  cp packaging/linux/neticora-runnerd.service packaging/linux/config.example.json packaging/linux/neticora-runnerd.sysusers.conf packaging/linux/neticora-runnerd.tmpfiles.conf packaging/linux/artifact-scope.json "$stage/packaging/"
  tar --sort=name --mtime="@$source_epoch" --owner=0 --group=0 --numeric-owner \
    -czf "$output_dir/runnerd-linux-$architecture.tar.gz" -C "$stage" .
  rm -rf -- "$stage"
  trap - EXIT
done
