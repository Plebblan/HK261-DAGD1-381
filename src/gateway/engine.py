"""Policy engine implementing gateway decision-making."""

from __future__ import annotations

from typing import Any

from src.common.types import GatewayRequest, VerdictRecord


def decide(request: GatewayRequest, *, allowlist: list[dict[str, Any]] | None = None) -> VerdictRecord:
    """Return a gateway verdict for a request.

    This first iteration intentionally defaults to allowing requests unless the
    caller explicitly asks for a stricter decision policy.
    """
    _ = allowlist
    return VerdictRecord(action="allow", reason="default allow policy", tags=())
