# Sandbox cleanup

The Kata cleanup path verifies original runtime and storage ownership before
removing sandbox metadata. Broker-backed Kata/storage migration remains incomplete;
production admission stays disabled. Container absence alone does not establish
VM shutdown, storage detachment or safe reuse.

## Ownership and cleanup guards

Cleanup retains the original execution, block allocation, cgroup, runtime peer and
captured directory device/inode. It verifies Docker object/network state, VM process
absence, the owned empty cgroup and storage identity before reporting disposal.
Unknown ownership, foreign entries, held references, unreadable state or incomplete
observations retain the cleanup obligation and reserved capacity.

Metadata traversal is sequential and bounded. It reads at most 64 names at a time,
limits work to 4,096 entries per captured directory per request, and enforces a
maximum depth of 32. Every removal repeats the relevant ownership, filesystem,
mount, process, descriptor/mapping and namespace checks, revalidates the inode, and
syncs the parent directory. No cached negative observation authorizes deletion.

Decoders and buffers may be reused for exactly matching freshly read input.
Dynamic filesystem, descriptor, cwd/root and mount observations remain fresh.
Changed, missing or unsupported input cannot reuse an earlier absence decision.

## Interrupted cleanup

A request can yield with a non-successful result after bounded work or cancellation.
The removed prefix is durably recorded by the filesystem; the original ownership
record remains authoritative. A later request starts from the same captured
identity and repeats all guards. It does not trust a saved negative snapshot,
replace the resource, reset its journal or discard unresolved entries.

Runtime removal and physical absence do not release the reservation. Storage,
cgroup, network and sandbox disposal must be independently verified, followed by
the normal journal/event/final-acknowledgment protocol. Boot or endpoint changes
require the corresponding authorized recovery path rather than edited identity
fields.

## Qualification

Use the [qualification harness](QUALIFICATION-HARNESS.md) for protected source
builds, disposable-host prerequisites and the native gate. Its stress mode uses
4,096 metadata entries and 32 surviving workers. Each cleanup request has a
110-second deadline inside the observer's 120-second client deadline. Retain source
and binary hashes, setup details, load, guard timings and JSON results outside Git.

A timeout or partial prefix is incomplete cleanup. The held-reference case must
identify the reference-caused refusal; unrelated errors or fixture teardown are
not successful disposal. Do not extend the production request budget or skip
checks to satisfy a benchmark.

The current implementation has no atomic kernel fence between its final reference
observation and unlink. `TestNativeSandboxLateReferenceAtUnlink` exercises that gap;
a passing earlier test subset does not establish protection. Preserve failed
qualification and quarantine behavior until the implemented architecture satisfies
the replacement cleanup contract. No consolidated negative-reference cache or
universal inode-destruction guarantee is supported.
