#!/usr/bin/env python3
"""Read-only audit of one deliberately quarantined disposable-host fixture.

This proves retention across a boot boundary, not automatic cross-boot recovery.
Never rewrites a ledger, starts a workload, disposes a resource or releases capacity.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--docker", default="/opt/neticora-runnerd-lab/docker-29.9.3/bin/docker")
    args = parser.parse_args()
    require(os.geteuid() == 0 and Path("/etc/neticora-runnerd-lab").is_file(), "root on marked disposable host required")
    evidence = json.loads(args.evidence.read_text())
    require(evidence["purpose"] == "runnerd-d2-held-reboot" and evidence["productionAdmission"] is False, "wrong evidence scope")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    previous = json.loads(args.previous.read_text()) if args.previous else evidence
    require(boot != previous["boot"], "boot boundary not observed")
    if args.previous:
        require(previous["evidenceSha256"] == hashlib.sha256(args.evidence.read_bytes()).hexdigest(), "different original evidence")
    hashes = {}
    for name in ("ledger", "journal"):
        root = Path(evidence[name])
        require(root.is_dir() and str(root).startswith("/var/lib/neticora-phase-d-"), "unexpected protected fixture path")
        for path in root.rglob("*"):
            require(not path.is_symlink(), "unexpected evidence symlink")
            if path.is_file() and path.name != "instance.lock":
                hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    require(hashes == evidence["hashes"], "original journal or ledger changed; retain all evidence")
    ledger = Path(evidence["ledger"])
    resources = [json.loads(path.read_text()) for path in (ledger / "resources").glob("*.json")]
    require(len(resources) == 1, "unexpected physical resource set")
    physical = resources[0]
    original = physical["operations"]["CreateExecution"]
    require(physical["version"] == "runnerd-broker-resource-v2" and physical["boot"] == evidence["boot"], "original physical ownership lost")
    # A pending create is logically quarantined even when the last durable
    # phase is ALLOCATED: SIGKILL happens before a failure handler can write it.
    require(physical["pending"] == original["operationId"] and not physical["resourceId"] and physical["state"] in ("ALLOCATED", "QUARANTINED"), "original unknown creation not retained")
    require(not physical["completed"].get(original["operationId"]), "unknown creation completed")
    receipt = json.loads((ledger / (original["operationId"] + ".json")).read_text())
    challenge = json.loads((ledger / "challenges" / (original["operationId"] + ".json")).read_text())
    require(receipt["state"] == "RECOVERY_REQUIRED" and receipt["binding"] == physical["binding"], "original obligation lost")
    require(challenge["state"] == "CONSUMED" and challenge["request"] == original, "original single-use challenge lost")
    database = Path(evidence["journal"]) / "journal.db"
    require(not Path(str(database) + "-wal").exists(), "offline audit requires cleanly closed native SQLite journal")
    with sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1", uri=True) as connection:
        require(connection.execute("PRAGMA integrity_check").fetchone() == ("ok",), "native journal integrity failed")
        rows = connection.execute("SELECT e.execution_id,e.state,r.released FROM executions e JOIN reservations r USING(execution_id,generation)").fetchall()
    require(len(rows) == 1 and rows[0][0] == original["executionId"] and rows[0][1] != "cleaned" and rows[0][2] == 0, "native reservation prematurely released")
    require(any(path.endswith(".creation.json") for path in hashes), "original native creation claim missing")
    installation = evidence["scope"]["InstallationID"]
    result = subprocess.run([args.docker, "-H", "unix:///run/runnerd09-docker.sock", "ps", "-aq", "--filter", "label=com.neticora.runnerd.installation=" + installation], check=True, capture_output=True, text=True)
    require(not result.stdout.strip(), "unexpected execution resource; retain ownership")
    # Verify the read-only SQLite inspection did not alter any original bytes.
    require(all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest for path, digest in hashes.items()), "audit changed original evidence")
    output = {"purpose": "runnerd-d2-held-reboot-audit", "evidenceSha256": hashlib.sha256(args.evidence.read_bytes()).hexdigest(), "boot": boot, "originalBoot": evidence["boot"], "filesVerified": len(hashes), "executionId": original["executionId"], "operationId": original["operationId"], "pendingRetained": True, "challengeConsumed": True, "reservationReleased": False, "dockerResources": 0, "automaticCrossBootRecoveryQualified": False, "productionAdmission": False, "observedAtUnix": int(time.time())}
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(output, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(args.output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps(output))


if __name__ == "__main__":
    main()
