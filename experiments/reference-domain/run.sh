#!/usr/bin/env bash
# Disposable component experiment. Never part of runnerd installation/admission.
set -euo pipefail
[[ ${RUNNERD09_REFERENCE_DOMAIN_PROTOTYPE:-} == 1 && $EUID == 0 ]]
[[ -e /etc/neticora-runnerd-lab ]]
[[ $(readlink /proc/self/ns/mnt) != "$(readlink /proc/1/ns/mnt)" ]]
runnerd_domain_output=${1:?usage: run.sh FRESH_ABSOLUTE_OUTPUT_DIRECTORY}
[[ $runnerd_domain_output == /var/tmp/runnerd09-domain-*/* ]]
[[ $(realpath -m -- "$runnerd_domain_output") == "$runnerd_domain_output" ]]
umask 077
mkdir -m 0700 -- "$runnerd_domain_output"
runnerd_domain_source=$(dirname -- "$(realpath -- "${BASH_SOURCE[0]}")")
runnerd_domain_backing=$runnerd_domain_output/metadata.ext4
runnerd_domain_loop=
runnerd_domain_cleanup() {
  local runnerd_domain_status=$?
  if [[ -n $runnerd_domain_loop ]]; then
    if [[ $(losetup --list --noheadings --output BACK-FILE "$runnerd_domain_loop") == "$runnerd_domain_backing" ]]; then
      losetup --detach "$runnerd_domain_loop" || runnerd_domain_status=2
    else
      echo 'Owned loop identity changed; retain fixture for reconciliation.' >&2
      runnerd_domain_status=2
    fi
  fi
  exit "$runnerd_domain_status"
}
trap runnerd_domain_cleanup EXIT
uname -a > "$runnerd_domain_output/kernel.txt"
cc --version > "$runnerd_domain_output/compiler.txt"
cc -O2 -Wall -Wextra -Werror "$runnerd_domain_source/retire_probe.c" \
  -o "$runnerd_domain_output/retire-probe"
sha256sum "$runnerd_domain_source/retire_probe.c" "$runnerd_domain_source/run.sh" \
  "$runnerd_domain_output/retire-probe" > "$runnerd_domain_output/provenance.sha256"
truncate -s 64M -- "$runnerd_domain_backing"
runnerd_domain_loop=$(losetup --find --show --nooverlap "$runnerd_domain_backing")
[[ $runnerd_domain_loop =~ ^/dev/loop[0-9]+$ ]]
[[ $(losetup --list --noheadings --output BACK-FILE "$runnerd_domain_loop") == "$runnerd_domain_backing" ]]
printf '%s\n' "$runnerd_domain_loop" > "$runnerd_domain_output/owned-loop.txt"
mkfs.ext4 -q -F "$runnerd_domain_loop" > "$runnerd_domain_output/mkfs.stdout" \
  2> "$runnerd_domain_output/mkfs.stderr"
mkdir -m 0700 -- "$runnerd_domain_output/fixture"
"$runnerd_domain_output/retire-probe" "$runnerd_domain_loop" \
  "$runnerd_domain_output/fixture" "$runnerd_domain_backing" \
  > "$runnerd_domain_output/observations.jsonl" 2> "$runnerd_domain_output/probe.stderr"
