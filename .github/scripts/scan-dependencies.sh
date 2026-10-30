#!/usr/bin/env bash
set -euo pipefail
export GOTOOLCHAIN=local
# Separate online preparation/database lookup from offline qualification.
scan_dir=$(mktemp -d)
trap 'rm -rf -- "$scan_dir"' EXIT
repo_root=$(git rev-parse --show-toplevel)
for module in cmd/runnerd cmd/runnerd-verify api/tools/cmd/contract api/protocol api/conformance; do
  (cd "$module" && go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 -json -scan module) > "$scan_dir/report.json"
  module_file=$(cd "$module" && go env GOMOD)
  python3 "$repo_root/.github/scripts/check-vulnerability-scan.py" "$scan_dir/report.json" "$(dirname "$module_file")"
done
git diff --exit-code -- go.mod go.sum api
