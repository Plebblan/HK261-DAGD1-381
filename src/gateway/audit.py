"""Audit and reporting helpers for requests and findings."""

from __future__ import annotations


def summarize_decision(decision: str) -> str:
    """Convert a raw decision into a readable audit message."""
    return f"decision={decision}"
