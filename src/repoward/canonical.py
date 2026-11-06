"""One invariant byte form for everything that gets hashed."""

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    """Serialize to sorted, compact UTF-8 JSON.

    Over this project's data (ASCII keys, no floats) the output matches RFC 8785.
    """
    text = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return text.encode("utf-8", "surrogatepass")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
