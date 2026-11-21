"""Core request and verdict types used by the gateway and proxy layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class GatewayRequest:
    """Normalized request delivered to the gateway policy engine."""

    method: str
    host: str
    path: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes | str | None = None
    actor: str | None = None
    tags: tuple[str, ...] = ()
    origin: str = "capture"
    run_id: str | None = None


@dataclass(frozen=True)
class VerdictRecord:
    """Decision returned by the gateway after policy evaluation."""

    action: str
    reason: str = ""
    allowlist_rule: str | None = None
    tags: tuple[str, ...] = ()
    metadata: dict[str, Any] | None = None
