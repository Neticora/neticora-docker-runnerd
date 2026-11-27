# Standalone Kata sandbox cleanup

The trusted host service uses its bound local Docker peer to stop and remove
the exact journal-owned container. Docker, containerd and Kata own runtime
metadata removal. Runnerd checks signed runtime roots for the exact
container's absence and checks the host for its shim and VMM. Runnerd does
not recursively delete runtime metadata. Remaining metadata holds cleanup
until the original runtime removes it.

An authenticated platform cleanup command and durable native cleanup intent
precede Docker removal. Runtime identity, enrollment scope, execution,
generation, cgroup and physical allocation stay bound to the original
attempt. Before finalizing, Runnerd verifies Docker inventory and network
detachment, the owned cgroup's retirement, and exact loop, device and backing
storage state. Sticky cache clones remain journal-owned. Only an eligible
successful attempt can publish a detached clone as a cache generation.

Unexpected ownership, filesystem identity, runtime residue or an attached
device prevents a cleaned event. An uncertain Docker peer never becomes a
source of absence evidence. A changed boot or peer needs the independently
signed and platform-committed cleanup-only recovery path. Physical cleanup
precedes the durable cleaned event. The platform releases its reservation
after the original final ACK.

[#328](https://github.com/Neticora/neticora-alpha/issues/328) measured and
stress-tested recursive metadata deletion for the retired observer and broker
design. The shipped path has no such deleter. Its applicable safety
requirements are covered by the standalone runtime absence and ownership
checks and the [installed qualification](QUALIFICATION-HARNESS.md#standalone-teardown-qualification).
