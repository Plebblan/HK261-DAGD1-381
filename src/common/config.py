"""Configuration loading and validation helpers for gateway configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def load_config(path: str | Path) -> dict[str, Any]:
    """Load a YAML configuration file.

    The implementation intentionally stays thin until the project adds the real
    config parser. The first iteration only validates the file path and returns
    the parsed object so callers can work against a stable API.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    # Replace with the real YAML loader once the config schema is finalized.
    return {"path": str(config_path), "loaded": True}


def validate_config(config: dict[str, Any]) -> None:
    """Ensure the minimum required fields are present for the gateway."""
    policy = config.get("undocumented_policy")
    if policy not in {"block", "hold", "allow_and_flag", None}:
        raise ValueError("undocumented_policy must be block, hold, allow_and_flag, or null")
