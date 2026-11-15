"""Domain models persisted by the SQLite adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RunRecord:
    """Top-level metadata for a single run."""

    run_id: str
    target: str
    status: str = "created"
    config_hash: str | None = None
    allowlist_hash: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """Security or policy finding emitted during a run."""

    finding_id: str
    run_id: str
    title: str
    summary: str = ""
    severity: str = "info"
    metadata: dict[str, Any] = field(default_factory=dict)
