#!/usr/bin/env bash
set -euo pipefail
export GOTOOLCHAIN=local
# Separate online preparation/database lookup from offline qualification.
for module in cmd/runnerd api/tools/cmd/contract api/protocol api/conformance; do
  (cd "$module" && go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 -scan module)
done
git diff --exit-code -- go.mod go.sum api
