#!/usr/bin/env python3
"""Fail qualification when required native coverage was skipped or omitted."""
import json
import sys

PACKAGE = "github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
REQUIRED = frozenset({
    "TestStandaloneNativeSandboxAbsence/retains-runtime-residue",
    "TestStandaloneNativeSandboxAbsence/rejects-replaced-parent",
    "TestStandaloneNativeSandboxAbsence/accepts-exact-absence",
    "TestStandaloneNativeSandboxAbsence/requires-Kata-restore-state-and-share-on-one-volume",
    "TestStandalonePreflightPinsJournalAndRejectsDrift",
    "TestBlockReleaseIntentPreservesAmbiguity",
    "TestBlockDurableOwnershipSurvivesReopenAndRejectsCorruption",
    "TestMultiBlockReleaseNeedsOwnDurableTombstoneAndKeepsPeerReservation",
    "TestCorruptIndexCannotBeHiddenByReleasedExecutionTombstone",
    "TestHostCgroupReadinessFencesConflictsAndInvalidLimits/populated",
    "TestConfiguredOrActiveSliceIsNeverEmptyCapacity",
    "TestProcPrefixFieldsPreservesWhitespaceAndColumns",
    "TestSandboxMountDecoderPreservesEscapes",
    "TestProcDecoderUsesFreshBytesAndCurrentTarget",
    "TestProcDecoderBudgetAndLargeMapsDoNotSkipChecks",
    "TestProcMountDecoderExactContentAndCancellation",
    "TestProcessTasksFailClosed",
    "TestProcessTaskEnumerationCancellation",
    "TestBothScannersFenceObservableGroupWithoutTasks",
    "TestBothScannersHonorCanceledContext",
    "TestSurvivingWorkerRetainsMmapAfterFDClosure/unlinked=false",
    "TestSurvivingWorkerRetainsMmapAfterFDClosure/unlinked=true",
    "TestSurvivingWorkerRetainsIndependentMountNamespace",
})


def require_native(events):
    required = REQUIRED
    passed = set()
    package_passed = False
    for event in events:
        if event.get("Package") != PACKAGE:
            continue
        action, test = event.get("Action"), event.get("Test")
        if action == "fail" or (action == "skip" and test in required):
            raise ValueError("Required native qualification failed or skipped")
        if action == "pass":
            if test:
                passed.add(test)
            else:
                package_passed = True
    if not package_passed or not required.issubset(passed):
        raise ValueError("Incomplete native qualification coverage")
    return sorted(required)


if __name__ == "__main__":
    try:
        with open(sys.argv[1], encoding="utf-8") as stream:
            tests = require_native(
                (json.loads(line) for line in stream if line.strip()),
            )
        print(json.dumps({"nativeTests": tests, "status": "passed",
                          "scope": "Linux native regressions; not Kata runtime qualification"}))
    except (OSError, ValueError, KeyError, IndexError) as error:
        print(f"Native qualification refused: {error}", file=sys.stderr)
        sys.exit(1)
