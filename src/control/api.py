"""Control-plane API for findings, status, and kill-switch endpoints."""

from __future__ import annotations


def health() -> dict[str, str]:
    """Return the service health payload for a control API."""
    return {"status": "ok"}
