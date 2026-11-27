# Customer-managed Kata networking

Runtime isolation and destination policy are separate controls. Each execution
owns its Kata guest, nested Docker daemon, containers and private services. Jobs
and services inside one guest may communicate. Other executions must not reach
those private services or discover their private network. Guest root must not
administer host interfaces, routes, firewall, DNS or proxies, or access host
Docker/containerd, broker/control IPC, credentials, KVM or backing block devices.

Internet, GitHub, registries and customer internal services follow the customer's
documented approved destination policy. Private address space is not inherently
forbidden. Neticora does not require a customer-wide firewall, egress allowlist,
Kubernetes CNI or Neticora-operated egress proxy. Sensitive management interfaces
must be explicitly protected even when other destinations on that host or subnet
are approved. HTTP authentication failures alone do not prove network isolation.

## Qualification network guard

The operator preprovisions a dedicated runtime bridge with inter-container
communication disabled, then installs owned bridge/inet filter tables scoped to
that bridge. The bridge table prevents traffic between executions, including L2
discovery. The inet table blocks guest ingress to host endpoints and forwarding
to protected management destinations. It must account for IPv4 and IPv6, host
gateway addresses, forwarded ports and alternate management addresses. Explicit
customer service exceptions must remain narrower than management destinations.
Unrelated customer firewall, routing, DNS and proxy configuration is preserved.

The broker does not provision networks or mutate firewall policy. Its optional
`runtime.kata.networkGuardFile` names a root-private descriptor:

```json
{
  "version": "runnerd-network-guard-v1",
  "networkId": "<exact 64-character Docker network ID>",
  "bridge": "nr9-f4",
  "ipv6": true,
  "nftBinary": "/usr/sbin/nft",
  "table": "nr9_f4",
  "inetSha256": "<canonical inet table hash>",
  "bridgeSha256": "<canonical bridge table hash>"
}
```

The descriptor bytes and nft executable hash must appear in the independently
signed Kata manifest's `files` map. The broker checks the exact Docker bridge,
driver, scope, IPv6 setting and disabled inter-container communication. It reads
both live nft tables with fixed, bounded read-only commands. Table hashes cover
ordered rules, expressions, chain priorities and policies; only nft version
metadata and object handles are excluded. Stateful counters and indirect table
objects are unsupported. Operators must review the actual rule semantics before
signing the manifest; a matching hash alone is not an isolation assessment.

Checks run at broker startup and at each image/create/start admission guard.
Missing or changed guards reject new effects. Stop, disposal, original ownership
and finalization remain independent, so a failed network guard cannot authorize
replacement resources or erase cleanup obligations. Reading nft requires the
installed broker service's appropriate capability; the controller receives none.

This guard remains engineering qualification functionality. Production admission
stays disabled pending actual adversarial dual-guest, management-interface,
IPv6, discovery, DNS rebinding, forwarded-port and proxy-path tests on the exact
signed tuple. Preserve before/after customer configuration evidence and record
unsupported or untested paths explicitly.
