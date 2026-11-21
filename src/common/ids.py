"""IDs for events, runs, and persisted records."""

from __future__ import annotations

import uuid


def make_event_id() -> str:
    """Create a unique event identifier."""
    return uuid.uuid4().hex


def make_run_id() -> str:
    """Create a unique run identifier."""
    return uuid.uuid4().hex
