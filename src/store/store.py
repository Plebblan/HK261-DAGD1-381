"""SQLite-backed store interface.

This module defines the adapter boundary described by the architecture document.
The first cut intentionally keeps the API minimal and focuses on the shape of the
implementation rather than live database logic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class Store:
    """Minimal store adapter for events and model persistence."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def create_run(self, *, run_id: str, target: str, **kwargs: Any) -> None:
        """Create a run record when a new session begins."""
        _ = (run_id, target, kwargs)

    def append_event(self, *, event_id: str, run_id: str, **kwargs: Any) -> None:
        """Append a single event to the datastore."""
        _ = (event_id, run_id, kwargs)

    def append_events(self, events: list[dict[str, Any]]) -> None:
        """Append multiple events atomically."""
        _ = events

    def get_events(self, *, run_id: str, **kwargs: Any) -> list[dict[str, Any]]:
        """Return events in insertion order for a run."""
        _ = (run_id, kwargs)
        return []

    def put_model(self, *, model_name: str, version: str, payload: Any) -> None:
        """Write a versioned model payload."""
        _ = (model_name, version, payload)

    def get_model(self, *, model_name: str, version: str | None = None) -> Any:
        """Retrieve a model payload by name and optional version."""
        _ = (model_name, version)
        return None

    def upsert_finding(self, *, finding_id: str, **kwargs: Any) -> None:
        """Insert or update a finding."""
        _ = (finding_id, kwargs)

    def list_findings(self, *, run_id: str, **kwargs: Any) -> list[dict[str, Any]]:
        """List findings for a run."""
        _ = (run_id, kwargs)
        return []
