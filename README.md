# neticora-docker-runnerd

Canonical Neticora host-protocol contracts and Go bindings for the planned
standalone runner manager. No executable agent or accepted runtime is included.
The existing repository/module identity is retained pending the coordinated
release-name decision.

## Contract layout

- `api/host-protocol.v1.yaml`: canonical OpenAPI 3.1 / JSON Schema 2020-12.
- `api/fixtures/`: shared wire, canonicalization and replay vectors.
- `api/tools/`: pinned Go generator, offline drift checks and failure tests.
- `api/protocol/`: generated models, lossless nullable fields and validated decode.
- `api/conformance/`: independent schema, logical hash and identity conformance.

See [the protocol specification](api/README.md) and
[Go tooling and qualification](api/GO-BINDINGS.md) for commands and limitations.
Alpha imports the canonical schema and fixtures through an immutable source lock;
the Go tooling does not require the alpha checkout or Node.js.
