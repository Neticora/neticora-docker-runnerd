#!/usr/bin/env python3
"""Fail qualification when required native coverage was skipped or omitted."""
import json
import os
import sys

PACKAGE = "github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
REQUIRED = frozenset({
    "TestNativeSandboxResidueCleanup",
    "TestNativeSandboxHistoricalReconciliationRetainsResidue",
    "TestNativeSandboxHeldReferenceRetainsOwnership",
    "TestNativeSandboxReplacementAndGuardRejectDeletion",
    "TestNativeSandboxCwdRetainsDirectory",
    "TestNativeSandboxHiddenWorkerMountRetainsDirectory",
    "TestNativeSandboxUnlinkedDirectoryRetainsReference",
    "TestNativeSandboxForeignEntriesRemainFenced",
    "TestNativeSandboxPrivateAnchorControlsRuntimeModes",
    "TestNativeSandboxCleanupBudgetIsResumable",
    "TestNativeSandboxLargeDirectoryUsesRequestBudget",
    "TestNativeSandboxCleanupSurvivesProcessCrash",
    "TestNativeSandboxLateReferenceAtUnlink",
    "TestNativeSandboxReferenceTypesFromSurvivingThread/fd",
    "TestNativeSandboxReferenceTypesFromSurvivingThread/opath",
    "TestNativeSandboxReferenceTypesFromSurvivingThread/dir",
    "TestNativeSandboxReferenceTypesFromSurvivingThread/cwd",
    "TestNativeSandboxReferenceTypesFromSurvivingThread/root",
    "TestNativeSandboxReferenceTypesFromSurvivingThread/mmap",
    "TestNativeSandboxReferenceTypesFromSurvivingThread/namespace-hidden-bind",
    "TestNativeSandboxReferenceAcquiredDuringMapsRead/fd",
    "TestNativeSandboxReferenceAcquiredDuringMapsRead/opath",
    "TestNativeSandboxReferenceAcquiredDuringMapsRead/mmap",
    "TestProcPrefixFieldsPreservesWhitespaceAndColumns",
    "TestSandboxMountDecoderPreservesEscapes",
    "TestProcDecoderUsesFreshBytesAndCurrentTarget",
    "TestProcDecoderBudgetAndLargeMapsDoNotSkipChecks",
    "TestProcMountDecoderExactContentAndCancellation",
    "TestProcReadBuffersDoNotReuseObservationBytes",
    "TestProcessTasksFailClosed",
    "TestProcessTaskEnumerationCancellation",
    "TestBothScannersFenceObservableGroupWithoutTasks",
    "TestBothScannersHonorCanceledContext",
    "TestSurvivingWorkerRetainsMmapAfterFDClosure/unlinked=false",
    "TestSurvivingWorkerRetainsMmapAfterFDClosure/unlinked=true",
    "TestSurvivingWorkerRetainsIndependentMountNamespace",
})
STRESS_REQUIRED = frozenset({
    "TestNativeSandboxBusyHostCleanupBudget/retained-reference=false",
    "TestNativeSandboxBusyHostCleanupBudget/retained-reference=true",
})


def require_native(events, require_stress=False):
    required = REQUIRED | STRESS_REQUIRED if require_stress else REQUIRED
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
                require_stress=os.environ.get("RUNNERD09_SANDBOX_STRESS") == "1",
            )
        print(json.dumps({"nativeTests": tests, "status": "passed",
                          "scope": "Linux native regressions; not Kata runtime qualification"}))
    except (OSError, ValueError, KeyError, IndexError) as error:
        print(f"Native qualification refused: {error}", file=sys.stderr)
        sys.exit(1)
