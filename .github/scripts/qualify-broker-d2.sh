#!/usr/bin/env bash
# Disposable installed-service campaign. This does not qualify production.
set -euo pipefail
umask 077
unset RUNNERD_D2_CRASH_OPERATION RUNNERD_D2_CRASH_POINT RUNNERD_D2_CONTROLLER_CRASH
[[ $(id -u) == 0 && -f /etc/neticora-runnerd-lab && $# == 5 ]]
d2_test=$1
d2_broker=$2
d2_image=$3
d2_network=$4
d2_evidence=$5
[[ $d2_test = /* && $d2_broker = /* && $d2_evidence = /var/lib/* ]]
[[ -x $d2_test && -x $d2_broker && $d2_image == *@sha256:* && $d2_network =~ ^[a-f0-9]{64}$ ]]
for d2_binary in "$d2_test" "$d2_broker"; do
  [[ $(stat -c '%u' "$d2_binary") == 0 && ! -L $d2_binary ]]
  [[ $(stat -c '%a' "$d2_binary") == 755 ]]
done
if ! getent passwd 10002 >/dev/null; then
  ! getent group 10002 >/dev/null
  groupadd --gid 10002 neticora-d2-controller
  useradd --system --uid 10002 --gid 10002 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin neticora-d2-controller
fi
[[ $(getent passwd 10002 | cut -d: -f1) == neticora-d2-controller ]]
[[ $(id -G neticora-d2-controller) == 10002 ]]
[[ ! -e $d2_evidence ]]
install -d -o root -g root -m 0700 "$d2_evidence"
sha256sum "$d2_test" "$d2_broker" > "$d2_evidence/binary.sha256"
for d2_case in parallel CreateExecution StartExecution RemoveExecution controller; do
  d2_fault=()
  if [[ $d2_case == controller ]]; then
    d2_fault=(RUNNERD_D2_CONTROLLER_CRASH=1)
  elif [[ $d2_case != parallel ]]; then
    d2_fault=(RUNNERD_D2_CRASH_OPERATION="$d2_case" RUNNERD_D2_CRASH_POINT=after-effect)
  fi
  if env RUNNERD_D2_SYSTEMD=1 RUNNERD_D2_CONTROLLED_WORKLOAD=1 RUNNERD_D2_BROKER_BINARY="$d2_broker" RUNNERD_D2_JOBS=2 \
      RUNNERD_PHASE_D_ENDPOINT=unix:///run/runnerd09-docker.sock RUNNERD_PHASE_D_IMAGE="$d2_image" \
      RUNNERD_PHASE_D_NETWORK="$d2_network" TMPDIR=/var/tmp "${d2_fault[@]}" \
      "$d2_test" -test.v -test.run '^TestPhaseDControllerRealDocker$' -test.timeout 3m \
      > "$d2_evidence/$d2_case.log" 2>&1; then
    printf '%s: PASS\n' "$d2_case"
  else
    tail -n 35 "$d2_evidence/$d2_case.log"
    printf '%s: FAIL; preserve ownership and evidence at %s\n' "$d2_case" "$d2_evidence" >&2
    exit 1
  fi
done
printf '%s\n' 'Installed qualification campaign passed; production admission remains disabled.'
