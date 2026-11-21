"""HAR import for ingestion-only events."""

from __future__ import annotations

from pathlib import Path


def import_har(path: str | Path) -> dict[str, str]:
    """Placeholder import routine for HAR files."""
    return {"path": str(Path(path)), "status": "imported"}
