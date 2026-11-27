#!/usr/bin/env bash
set -euo pipefail
umask 077
output_dir=${1:?usage: build-qualification.sh FRESH_ABSOLUTE_PRIVATE_OUTPUT}
[[ "$output_dir" = /* && ! -e "$output_dir" && ! -L "$output_dir" ]] || exit 2
mkdir -m 0700 -- "$output_dir"
export GOTOOLCHAIN=local
python3 packaging/capture-qualification.py before "$output_dir"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=true \
  -tags runnerd_qualification -o "$output_dir/runnerd-qualification" ./cmd/runnerd-qualification
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=true \
  -o "$output_dir/runnerd-config" ./cmd/runnerd-config
chmod 0500 "$output_dir/runnerd-qualification" "$output_dir/runnerd-config"
python3 packaging/capture-qualification.py after "$output_dir"
