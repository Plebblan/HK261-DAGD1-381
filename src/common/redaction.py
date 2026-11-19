"""Redaction helpers for request and response payloads."""

from __future__ import annotations

import re
from collections.abc import Mapping
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
_JWT = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])")
_SENSITIVE_KEY = re.compile(
    r"(?i)(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|client[_-]?secret)"
)


def redact_payload(payload: Any) -> Any:
    """Recursively mask credential fields and credential-like text values."""
    if isinstance(payload, Mapping):
        if isinstance(payload.get("name"), str) and _SENSITIVE_KEY.search(payload["name"]):
            return {**{key: redact_payload(value) for key, value in payload.items() if key != "value"}, "value": "[REDACTED]"}
        result = {}
        for key, value in payload.items():
            if isinstance(key, str) and _SENSITIVE_KEY.search(key):
                result[key] = "[REDACTED]"
            elif isinstance(key, str) and key.lower() in {"cookies", "cookie_jar"} and isinstance(value, list):
                result[key] = [
                    {**{name: redact_payload(item) for name, item in cookie.items() if name != "value"}, "value": "[REDACTED]"}
                    if isinstance(cookie, Mapping) and "value" in cookie else redact_payload(cookie)
                    for cookie in value
                ]
            else:
                result[key] = redact_payload(value)
        return result
    if isinstance(payload, (list, tuple)):
        return [redact_payload(value) for value in payload]
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", "replace")
    if isinstance(payload, str):
        return redact_log_text(payload)
    return payload


def redact_log_text(text: str) -> str:
    """Redact common credentials and labeled bodies from a log message."""
    text = _AUTH_HEADER.sub(r"\1[REDACTED]", text)
    text = _COOKIE_HEADER.sub(r"\1[REDACTED]", text)
    text = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", text)
    text = _BODY_FIELD.sub(r"\1[REDACTED]", text)
    return _JWT.sub("[REDACTED]", text)
