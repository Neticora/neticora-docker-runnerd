#!/usr/bin/env python3
"""Retain an action-produced bundle and its statement; verification is separate."""
import base64
import json
import sys
from pathlib import Path


source, output = Path(sys.argv[1]), Path(sys.argv[2])
raw = source.read_bytes()
if len(raw) > 1_000_000:
    raise SystemExit("Oversized provenance bundle")
bundle = json.loads(raw)
statement = base64.b64decode(bundle["dsseEnvelope"]["payload"], validate=True)
value = json.loads(statement)
if value.get("_type") != "https://in-toto.io/Statement/v1" or value.get("predicateType") != "https://slsa.dev/provenance/v1":
    raise SystemExit("Unsupported provenance format")
for name, data in [("provenance.sigstore.json", raw), ("provenance.json", statement)]:
    with (output / name).open("xb") as target:
        target.write(data)
