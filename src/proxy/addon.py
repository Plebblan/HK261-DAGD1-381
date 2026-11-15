"""mitmproxy addon that routes requests through the gateway engine."""

from __future__ import annotations

from typing import Any


def build_addon() -> dict[str, Any]:
    """Return the proxy addon configuration stub."""
    return {"name": "gateway-addon", "enabled": True}
