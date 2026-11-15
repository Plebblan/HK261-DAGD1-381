"""Redaction helpers for request and response payloads."""

from __future__ import annotations

from typing import Any


def redact_payload(payload: Any) -> Any:
    """Placeholder redaction policy for the first iteration.

    The real implementation must compute the raw-body hash before redaction and
    apply rule-based masking only afterward.
    """
    return payload
