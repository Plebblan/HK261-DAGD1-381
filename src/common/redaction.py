"""Redaction helpers for request and response payloads."""

from __future__ import annotations

import re
from typing import Any

_SECRET_ASSIGNMENT = re.compile(
    r"""(?i)(["']?(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key)["']?\s*[:=]\s*)(?:"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s,;}\]]+)"""
)
_AUTH_HEADER = re.compile(
    r"(?i)((?:proxy-)?authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+"
)
_COOKIE_HEADER = re.compile(r"(?im)((?:cookie|set-cookie)\s*[:=]\s*)[^\r\n]+")
_BODY_FIELD = re.compile(
    r"""(?i)(["']?(?:(?:request|response|raw)[_\s-]?)?(?:body|payload)["']?\s*[:=]\s*)(\{.*|\[.*|"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s,;]+)"""
)


def redact_payload(payload: Any) -> Any:
    """Placeholder redaction policy for the first iteration.

    The real implementation must compute the raw-body hash before redaction and
    apply rule-based masking only afterward.
    """
    return payload


def redact_log_text(text: str) -> str:
    """Redact common credentials and labeled bodies from a log message."""
    text = _AUTH_HEADER.sub(r"\1[REDACTED]", text)
    text = _COOKIE_HEADER.sub(r"\1[REDACTED]", text)
    text = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", text)
    return _BODY_FIELD.sub(r"\1[REDACTED]", text)
