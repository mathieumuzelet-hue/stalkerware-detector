"""Extract the signing certificate SHA-1 fingerprint(s) from a `dumpsys package` blob.

Echap stores SHA-1 hex fingerprints (40 hex chars), matching the standard Android
cert fingerprint format produced by `keytool -list -v` and `apksigner verify
--print-certs`. We hash the raw DER bytes (not the hex string) and return one
fingerprint per `PackageSignatures{...}` block — multi-signer APKs are rare but
real.
"""
from __future__ import annotations

import hashlib
import re

# `signatures=PackageSignatures{<id> [<hex_blob>]}` — the hex blob is the DER-encoded
# certificate. We hash the raw bytes (not the hex string) to match how Echap and other
# stalkerware indexes record cert fingerprints.
_SIGNATURES_LINE = re.compile(
    r"signatures=PackageSignatures\{[^\s]+\s+\[(?P<hex>[0-9a-fA-F]+)\]\}"
)


def extract_cert_sha1(dump: str) -> list[str]:
    """Return lowercase hex SHA-1 fingerprints for every signing cert found.

    Returns an empty list if no `PackageSignatures{...}` block is present or if
    every block's hex blob is malformed.
    """
    out: list[str] = []
    for m in _SIGNATURES_LINE.finditer(dump):
        hex_blob = m.group("hex")
        try:
            raw = bytes.fromhex(hex_blob)
        except ValueError:
            continue
        out.append(hashlib.sha1(raw).hexdigest())
    return out
