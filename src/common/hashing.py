"""Utilities for deterministic hashing and canonicalization."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest for raw bytes."""
    return hashlib.sha256(data).hexdigest()


def canonical_fingerprint(value: Any) -> str:
    """Return a stable JSON representation suitable for deduplicating content."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return sha256_hex(encoded.encode("utf-8"))


def response_hash(payload: bytes | str | None) -> str:
    """Hash a response body while tolerating missing payload data."""
    if payload is None:
        return sha256_hex(b"")
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return sha256_hex(payload)
