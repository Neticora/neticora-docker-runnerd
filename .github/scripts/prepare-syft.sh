#!/usr/bin/env bash
set -euo pipefail
destination=${1:?usage: prepare-syft.sh ABSOLUTE_NEW_DIRECTORY}
[[ "$destination" = /* && $(uname -s) == Linux && $(uname -m) == x86_64 ]] || exit 2
mkdir -m 0700 "$destination"
archive="$destination/syft.tar.gz"
curl --fail --silent --show-error --location --retry 3 \
  https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_linux_amd64.tar.gz -o "$archive"
# Immutable official release asset digest, independently pinned in reviewed CI.
printf '%s  %s\n' bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d "$archive" | sha256sum --check --status
tar -xzf "$archive" -C "$destination" syft
"$destination/syft" version
