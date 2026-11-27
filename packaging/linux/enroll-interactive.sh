#!/usr/bin/env bash
set -euo pipefail
# Run as the dedicated runnerd service user. Never paste tokens into argv.
[[ $# -ge 3 ]] || { echo 'Usage: enroll-interactive.sh ENDPOINT TENANT_UUID STATE_DIRECTORY [runnerd-enroll options]' >&2; exit 2; }
endpoint=$1 tenant=$2 state=$3
shift 3
binary=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../bin" && pwd)/runnerd-enroll
[[ -d "$state" && ! -L "$state" ]] || { echo 'Provision a service-owned 0700 state directory first.' >&2; exit 2; }
if [[ -e "$state/attempt.json" || -L "$state/attempt.json" ]]; then
  exec "$binary" --endpoint "$endpoint" --tenant-id "$tenant" --state-dir "$state" "$@"
fi
umask 077
token_file=$(mktemp "$state/ui-token.XXXXXXXX")
trap 'unset ui_token; rm -f -- "$token_file"' EXIT
IFS= read -r -s -p 'Paste UI enrollment token: ' ui_token </dev/tty
printf '\n' >/dev/tty
printf '%s' "$ui_token" >"$token_file"
unset ui_token
"$binary" --endpoint "$endpoint" --tenant-id "$tenant" --state-dir "$state" --token-file "$token_file" "$@"
