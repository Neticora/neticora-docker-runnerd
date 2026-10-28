#!/usr/bin/env bash
set -euo pipefail

# Dependencies are prepared separately. All qualification runs offline.
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local

case "${1:-}" in
  lint)
    unformatted=$(gofmt -l api)
    if [[ -n "$unformatted" ]]; then
      printf 'Go files require formatting:\n%s\n' "$unformatted" >&2
      exit 1
    fi
    for module in tools protocol conformance; do
      (cd "api/$module" && go vet -mod=readonly ./...)
    done
    ;;
  typecheck)
    # Compile production and test code without running test cases.
    for module in tools protocol conformance; do
      (cd "api/$module" && go test -count=1 -mod=readonly -vet=off -run '^$' ./...)
    done
    ;;
  unit-tests)
    for module in tools protocol; do
      (cd "api/$module" && go test -count=1 -mod=readonly -race ./...)
    done
    ;;
  build)
    # Keep build products outside the checkout.
    output_dir=$(mktemp -d)
    trap 'rm -rf -- "$output_dir"' EXIT
    (cd api/tools && go build -mod=readonly -o "$output_dir/contract" ./cmd/contract)
    (cd api/protocol && go build -mod=readonly ./...)
    ;;
  contract-validation)
    (cd api/tools && go run -mod=readonly ./cmd/contract)
    ;;
  protocol-conformance)
    (cd api/conformance && go test -count=1 -mod=readonly -v ./...)
    ;;
  *)
    printf 'Unknown contract check: %s\n' "${1:-<missing>}" >&2
    exit 2
    ;;
esac

# Check tracked and newly generated API files without rejecting unrelated edits.
git diff --exit-code -- api
git diff --cached --exit-code -- api
test -z "$(git ls-files --others --exclude-standard -- api)"
