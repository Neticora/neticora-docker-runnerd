# Host protocol v1 contract candidate

This directory is the canonical OpenAPI 3.1 and fixture source. It is an initial
contract implementation, not a deployed endpoint, agent runtime or accepted
platform. Alpha consumes exact Git commits and byte/checksum-verified copies.
The repository remains `Neticora/neticora-docker-runnerd` until a coordinated
module/repository/signing transition is performed.

`host-protocol.v1.yaml` uses JSON syntax (a YAML 1.2 subset). All wire objects
reject unknown properties in v1; unknown command kinds/enums reject. Evolve
recovery/admission compatibility explicitly rather than dropping unknown fields.
All component references are local. OpenAPI discriminator is annotation;
`oneOf` and `const`/`enum` determine union validation. Validation does not prove
authentication, capability qualification, durable acceptance or cleanup.

## Canonicalization: neticora-json-v1

Logical payloads contain null, booleans, well-formed Unicode strings, arrays,
objects and finite safe integers (absolute value <= 9007199254740991). Counters,
resource amounts and generations are canonical unsigned decimal strings;
UInt64String additionally enforces 0..18446744073709551615, and Generation > 0.
Never convert decimal strings through a floating-point number. Decimal strings
with leading zeroes, signs, fractional notation or whitespace reject.

Serialize objects with keys sorted by Unicode code point (equivalently UTF-8
byte order for well-formed strings), arrays in original order, no whitespace,
minimal JSON string escaping, literal Unicode/HTML characters and normalized
negative-zero integer 0. Reject undefined, non-JSON objects, lone surrogates,
non-integer/non-finite/unsafe numeric values. Do not normalize Unicode strings,
decimal strings or timestamps. Absence, null and empty arrays remain distinct.
Timestamps require the specified UTC millisecond form; reject invalid dates.
Hash the UTF-8 canonical bytes with SHA-256. Field order and gzip encoding do
not affect that logical hash. Hash a command/event's defined payload, excluding
its own payloadHash field; do not hash an envelope containing its own checksum.
Execution specHash similarly excludes its own specHash field. The receiving
application verifies the supplied digest against this defined payload before
replay/conflict decisions; schema-valid digests alone are not content proof.

## Identity and durable coordination

A repeated command ID with identical payload hash is replay; another hash is a
protocol conflict. Event replay requires the same ID, sequence and content hash;
a different event ID occupying the same stream sequence conflicts. These rules
are scoped by authenticated host, execution and generation, never global names.
Do not advance contiguous ACK across a gap. Complete inventory alone can repair
current observations but cannot manufacture lost provider/historical facts.

Persist accepted commands before durable ACK. Retain an execution's identity,
immutable spec, intents, observations/outbox and cleanup obligations across
restarts. State and required outgoing fact commit atomically. No external API
work inside a store transaction. Uncertain provider issuance never permits blind
retry; duplicate startRequestId resolves one issuance, including uncertainty.
Admission disablement preserves authenticated recovery, cancellation and events;
revoked credentials remain denied. Session epoch is server controlled.

Only proven-owned immutable runtime IDs/spec/generation may be adopted/stopped/
removed. Cleanup intent precedes destructive operations; CLEANED requires trusted
absence evidence. Provider completion never releases physical host reservations.
SQLite failure/restore semantics and host trust boundaries are specified by the
alpha recovery/threat ADRs. Future Kubernetes requires equivalent durable intent
or explicit protocol evolution, not a weaker interpretation of ACK.

## Fixtures and evidence

`fixtures/manifest.json` lists unique sorted relative file names and SHA-256 of
exact bytes. Corpus hash is SHA-256 of compact JSON of those sorted `{path,
sha256}` records; the manifest is separately hashed. The manifest is excluded
from corpus file entries to avoid self-reference. Extra fixture files reject.
Schema validation vectors, canonical bytes/hashes and identity vectors are
language-neutral. Exact uint64 limits are field-specific, not JS numeric limits.
Go and TypeScript reports must name the same protocol/schema/corpus identities.
Alpha conformance is not evidence of Go validation or live persistence/runtime
acceptance. A Go JSON Schema 2020-12 conformance harness under conformance/ validates the
same schema/hash/identity vectors offline after module download. Go SDK generation
remains separate upstream work; conformance does not implement the runtime.

Secret-bearing enrollment/token/start messages are transient authenticated TLS
exchanges. Never journal plaintext bootstrap/registration/admin credentials or
include them in events, labels or logs. StartResponse may carry only an approved
host-bound encrypted bootstrap envelope; encryption/auth and one-use delivery
must be qualified before endpoint implementation. No tuple is schedulable from
a HostCapabilities claim alone: SaaS accepted evidence, local policy and tenant/
pool authorization must all agree. No default Docker management socket in jobs.
