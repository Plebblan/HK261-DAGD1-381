"""Thin spec loader with operation normalization.

This is the boundary between raw OpenAPI documents and downstream analysis.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def load_spec(path: str | Path) -> dict[str, Any]:
    """Load an OpenAPI document without applying business logic.

    The architecture calls for a thin loader that resolves $ref values and
    normalizes operation metadata. This placeholder keeps the contract stable.
    """
    spec_path = Path(path)
    if not spec_path.exists():
        raise FileNotFoundError(f"OpenAPI spec not found: {spec_path}")
    return {"path": str(spec_path), "loaded": True}
