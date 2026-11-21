"""HAR export utilities if extension fields do not round-trip."""

from __future__ import annotations

from pathlib import Path


def export_har(path: str | Path) -> str:
    """Placeholder export routine for HAR files."""
    return str(Path(path))
