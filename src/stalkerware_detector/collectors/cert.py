"""Extract the signing certificate SHA-256 from a `dumpsys package` blob."""
from __future__ import annotations

import hashlib
import re

# `signatures=PackageSignatures{<id> [<hex_blob>]}` — the hex blob is the DER-encoded
# certificate. We hash the raw bytes (not the hex string) to match how Echap and other
# stalkerware indexes record cert fingerprints.
_SIGNATURES_LINE = re.compile(
    r"signatures=PackageSignatures\{[^\s]+\s+\[(?P<hex>[0-9a-fA-F]+)\]\}"
)


def extract_cert_sha256(dump: str) -> str | None:
    """Return the lowercase hex SHA-256 of the signing cert, or None if absent."""
    m = _SIGNATURES_LINE.search(dump)
    if not m:
        return None
    hex_blob = m.group("hex")
    try:
        raw = bytes.fromhex(hex_blob)
    except ValueError:
        return None
    return hashlib.sha256(raw).hexdigest()
