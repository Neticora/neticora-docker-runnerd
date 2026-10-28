#!/usr/bin/env bash
set -euo pipefail
: "${GH_REPO:?Repository required}"
controls=$(mktemp -d)
trap 'rm -rf -- "$controls"' EXIT
gh api "repos/$GH_REPO/environments/runnerd-release" > "$controls/environment.json"
gh api "repos/$GH_REPO/environments/runnerd-release/deployment-branch-policies?per_page=100" > "$controls/branches.json"
gh api "repos/$GH_REPO/rules/branches/main" > "$controls/rules.json"
python3 .github/scripts/check-release-controls.py "$controls/environment.json" "$controls/branches.json" "$controls/rules.json"
