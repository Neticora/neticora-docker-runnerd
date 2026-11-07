#!/usr/bin/env bash
# No signing keys, platform access or customer host sockets are needed here.
set -euo pipefail
runnerd_native_output=${1:?usage: qualify-kata-native.sh OUTPUT_DIRECTORY}
[[ "$runnerd_native_output" = /* && ! -L "$runnerd_native_output" ]] || exit 1
mkdir -p "$runnerd_native_output"
command -v cc > "$runnerd_native_output/compiler-path.txt"
cc --version > "$runnerd_native_output/compiler-version.txt"
go version > "$runnerd_native_output/go-version.txt"
uname -a > "$runnerd_native_output/host-kernel.txt"
export RUNNERD09_REQUIRE_NATIVE_TESTS=1
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
# pipefail propagates the test exit code; the independent JSON gate also rejects
# missing/skipped cases even if the package exits successfully.
go test -mod=readonly -race -count=1 -json \
  -run '^(TestProcessTasksFailClosed|TestProcessTaskEnumerationCancellation|TestBothScannersFenceObservableGroupWithoutTasks|TestBothScannersHonorCanceledContext|TestSurvivingWorkerRetainsMmapAfterFDClosure|TestSurvivingWorkerRetainsIndependentMountNamespace)$' \
  ./internal/katalinux 2> "$runnerd_native_output/native-tests.stderr" \
  | tee "$runnerd_native_output/native-tests.jsonl"
python3 .github/scripts/require_kata_native.py "$runnerd_native_output/native-tests.jsonl" \
  > "$runnerd_native_output/native-coverage.json"
