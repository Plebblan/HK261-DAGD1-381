"""Kill switch support for emergency traffic blocking."""

from __future__ import annotations


class KillSwitch:
    """Simple in-memory kill switch for the gateway."""

    def __init__(self) -> None:
        self.enabled = False

    def enable(self) -> None:
        self.enabled = True

    def disable(self) -> None:
        self.enabled = False

    def is_enabled(self) -> bool:
        return self.enabled
