<<<<<<< Updated upstream
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
=======
"""Kill switch support for emergency traffic blocking.

Triggering it stops forwarding immediately; draining the writer happens after
(Architecture.md section 6.2: stop forwarding first, then drain, then close).
"""

from __future__ import annotations

import threading


class KillSwitch:
    """Thread-safe in-memory kill switch shared by the engine and the control API."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason = ""

    def enable(self, reason: str = "manual") -> None:
        self._reason = reason
        self._event.set()

    def disable(self) -> None:
        self._event.clear()
        self._reason = ""

    def is_enabled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        return self._reason
>>>>>>> Stashed changes
