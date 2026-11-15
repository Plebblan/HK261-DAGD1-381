"""Export helpers for the SQLite store."""

from __future__ import annotations

from typing import Any, Iterable


def export_jsonl(rows: Iterable[dict[str, Any]], *, path: str) -> None:
    """Write a JSONL export of store rows."""
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write("\n")
