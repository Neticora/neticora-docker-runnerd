# Customer resource observations

Runnerd reports timestamped CPU, memory and selected filesystem observations.
Docker 1.56+ API aggregate storage and original verified running-container usage
are reported where available. Connection-only mode still reports zero qualified
capacity and empty execution profiles; host utilization never changes those facts.

An optional `telemetry` field accompanies the existing authenticated heartbeat.
It is independent of capability hashes, inventory generations/receipts, policy,
qualification, ownership, cleanup evidence and reservations. Protocol/schema and
fixture sources are committed in `api/`. Legacy heartbeats can omit telemetry.

CPU utilization is the host `/proc/stat` delta over the reported sampling window,
in basis points (2400 means 24%). First/reset samples are warming-up with null
usage, not zero. Memory is `/proc/meminfo` total minus available, not a workload
memory promise. Filesystem used is total minus free; available excludes reserved
blocks. Missing inode counters are null. Multiple selected paths may share a
filesystem ID; never add their totals together.

Docker values are separate logical daemon categories, not an additive physical
filesystem total. Unsupported old Docker aggregate APIs, negative/unknown counters,
permission errors and timeouts remain unavailable/null. There is no requirement
to change Docker configuration to obtain metrics. Optional `observationPaths`
selects additional filesystem paths; it does not impose a topology or threshold.
Filesystem probes and Docker observation requests are bounded. The execution-mode
observer uses a separate read-only adapter so a telemetry timeout cannot invalidate
the mutating runtime's journal checkpoint.

Per-execution samples require an original journal creation claim and inspected
plan. Unverified resources make the execution list incomplete, not empty/complete.
CPU time is cumulative nanoseconds; memory is cgroup usage including cache.
Writable-layer bytes can be null when no bounded measurement is available.

Customers choose capacity, partitioning, quotas, monitoring thresholds and alerts.
Runnerd does not guarantee that an active job cannot exhaust shared disk. It does
not cancel or refuse executions solely for observed utilization. Existing qualified
resource/concurrency limits, durable-write failures and cleanup/recovery fences
remain mandatory safety checks. See [execution storage](EXECUTION-STORAGE.md).

## Platform and monitoring

Deploy the nullable `runner_hosts.resourceTelemetry` migration and compatible
API/worker before upgrading agents that send the optional heartbeat field.
Old strict gateways reject unknown heartbeat fields. This is a staged migration;
normal package installation does not alter a platform database.

The tenant-authenticated host list/detail API exposes `resourceTelemetry` with
sample/receipt timestamps, current session/key/endpoint binding and freshness.
A replay does not refresh receipt time. Older/future/wrong-endpoint samples cannot
replace current observations. Legacy agents leave old observations to become stale.
These fields are display/monitoring data only and never grant host readiness.

The Runner Hosts details view displays usage and availability separately from
qualified capacity. Stale and unavailable samples remain visibly distinct. The
same authenticated API supports customer JSON monitoring adapters.

Prometheus text is available at:

```text
GET /api/v1/tenants/{tenantId}/runner-hosts/{hostId}/metrics
Authorization: Bearer <an existing platform monitoring-user session>
```

It uses the same tenant/view permissions as host details. It introduces no public
agent listener or new credential type. Customers must manage a suitable existing
API authentication integration and its lifetime for their monitoring platform.
A stale/unbound sample exports the freshness gauge and last observation time,
without re-exporting stale usage as a fresh scrape. No metric controls admission.
