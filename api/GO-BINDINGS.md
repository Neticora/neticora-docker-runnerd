# Go host-protocol bindings

The reviewed generation inputs and outputs are pinned in
`go-generation.lock.json`. `oapi-codegen` v2.8.1 provides OpenAPI 3.1 model
generation ([pinned upstream documentation](https://github.com/oapi-codegen/oapi-codegen/blob/v2.8.1/README.md)).
Go 1.27.3 is the qualified generation toolchain; both Go module graphs
and the original independent conformance graph have committed sums. The consumer
module path uses the existing repository identity, not a proposed repository name.
Lock provenance records both repositories participating in this contract flow:
the canonical source (`Neticora/neticora-docker-runnerd`) and current consumer
(`Neticora/neticora-alpha`).

## Install and check

Put Go 1.27.3 on PATH. Populate the dependency cache once, with normal Go module
checksum verification enabled:

```sh
for module in tools protocol conformance; do
  (cd "api/$module" && go mod download)
done
git diff --exit-code -- api
```

Use `go mod download` without `all`. These Go 1.25 modules explicitly list the
dependencies needed by their build/test graphs. `all` expands the download scope
and can append unrelated transitive checksums to `go.sum`, dirtying a pinned
checkout and invalidating generation provenance. Cache preparation must preserve
the committed module files. Keep clean-source and generation-lock checks enabled;
do not accept or hide checksum drift to get qualification to pass.

Generation checks and tests then run without remote module/schema resolution:

```sh
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
(cd api/tools && go run -mod=readonly ./cmd/contract)
(cd api/tools && go test -count=1 -mod=readonly ./...)
(cd api/protocol && go test -count=1 -mod=readonly -race ./...)
(cd api/protocol && go vet -mod=readonly ./...)
(cd api/conformance && go test -count=1 -mod=readonly -v ./...)
```

`--write` regenerates committed output using the reviewed input lock.
`--update-lock` is an explicit review operation after changing schema, fixture,
toolchain, module graph, overlay, configuration or generation implementation:

```sh
(cd api/tools && go run -mod=readonly ./cmd/contract --update-lock)
(cd api/tools && go run -mod=readonly ./cmd/contract)
```

Normal checks never rewrite the lock or tracked output. No generator is installed
globally. The separate tools module keeps generator dependencies out of the Go
protocol consumer. CI downloads dependencies in an explicit step and runs drift,
generated-model qualification and independent conformance with lookup disabled.

## Qualified representation

The canonical schema is unchanged by generation. The locked overlay supplies
Go-binding annotations: timestamps remain exact strings, and implicit JSON Schema
enum/const types are made explicit for the generator. Validation always uses the
original embedded canonical schema, not the overlay. The lock hashes the schema,
each fixture, manifest, generator modules/sums, configuration, overlay, wrapper
and generated output separately. External schema references and replacement
generator modules are rejected.

Use `protocol.DecodeHostHeartbeat`, `DecodeStartCommand`, etc. to validate the
original wire bytes before binding to generated types. `DecodeWire` is the
schema-indexed equivalent. Raw `json.Unmarshal`, casts and generated enum `Valid`
methods are not protocol validators or proof of authentication. In particular,
the generator's nullable-enum convenience constants are not the accepted wire
value set; only the canonical runtime validator defines that set.

Fixtures qualify strict nested/unknown-field rejection, unions, formats, exact
decimal bounds, optional/null/empty distinctions, generation and enum constraints.
Every accepted corpus vector must round-trip through its generated type without
changing parsed JSON meaning. Additional tests exercise absent/null/empty
bootstrap values, full uint64 boundaries, malformed input and redacted errors.
Validation also rejects duplicate JSON object keys at any nesting depth before
schema checks, and duplicate-key fixtures are enforced by both protocol runtime
tests and independent conformance tests. HostEvent mutation tests cover decode/
modify/re-encode, optional field clearing, struct construction and variant
switching to ensure stale union state is not retained across serialization.
Raw-byte Unicode fixtures additionally require lossless UTF-8/surrogate handling
before binding, preserve valid replacement/astral characters and distinguish URI
from IRI. Shared outbound fixtures reject incompatible command merges and missing
event observations; independent canonical reference checks detect structurally
valid messages whose hash became stale after mutation. Production Go outbound
builders/encoding and reusable hash APIs are explicitly deferred to Runnerd 02.
The independent Go harness still verifies canonical bytes, logical hashes and
identity replay/conflicts against the same fixture identities as TypeScript.
Generator tests run the actual CLI in temporary trees and reject manual model
edits, schema/configuration/tool/fixture drift and external references.

This qualification covers the schema features and shared corpus in protocol
1.0.0. It does not qualify arbitrary OpenAPI features, authenticate hosts, bind
capabilities to server authority, implement atomic persistence, or accept an OS,
Docker engine or isolation profile for execution. New schema constructs require
new fixtures and generator qualification before the lock is refreshed.
