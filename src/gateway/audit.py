<<<<<<< Updated upstream
"""Audit and reporting helpers for requests and findings."""

from __future__ import annotations


def summarize_decision(decision: str) -> str:
    """Convert a raw decision into a readable audit message."""
    return f"decision={decision}"
=======
"""Audit and gateway-response helpers.

Gateway verdicts are not target verdicts (D3/DR5): every blocked request gets a
marker header so neither the oracle nor a human can mistake a gateway 403 for an
application deny. Bodies and headers are deliberately not handled here; redaction
happens at the proxy boundary, after the raw-body hash is computed.
"""

from __future__ import annotations

from typing import Any

from src.common.types import GatewayRequest, Verdict

VERDICT_HEADER = "X-Gateway-Verdict"
REASON_HEADER = "X-Gateway-Reason"


def audit_fields(request: GatewayRequest, verdict: Verdict) -> dict[str, Any]:
    """Event columns (src/store/schema.sql) derivable from request + verdict."""
    return {
        "run_id": request.run_id,
        "origin": request.origin,
        "actor": request.actor,
        "operation_id": verdict.operation_id,
        "method": request.method.upper(),
        "host": f"{request.host}:{request.port}",
        "path": request.path,
        "query": request.query or None,
        "gateway_verdict": verdict.decision,
        "gateway_reason": verdict.reason,
        "rule_id": verdict.rule_id,
        "undocumented": "undocumented" in verdict.flags,
        "tag": "static" if "static" in verdict.flags else None,
    }


def block_response(verdict: Verdict) -> tuple[int, dict[str, str], bytes]:
    """Immediate response for a blocked request: (status, headers, body)."""
    if verdict.reason in {"audit_unavailable", "kill_switch"}:
        status = 503
    elif verdict.reason == "budget_exceeded":
        status = 429
    else:
        status = 403
    headers = {
        VERDICT_HEADER: "blocked",
        REASON_HEADER: verdict.reason,
        "Content-Type": "text/plain; charset=utf-8",
    }
    if verdict.retry_after_s:
        headers["Retry-After"] = str(max(1, round(verdict.retry_after_s)))
    return status, headers, f"blocked by gateway: {verdict.reason}\n".encode()


def summarize_decision(verdict: Verdict) -> str:
    """One-line readable audit message."""
    rule = f" rule={verdict.rule_id}" if verdict.rule_id else ""
    return f"decision={verdict.decision} reason={verdict.reason}{rule} allowlist={verdict.allowlist_hash[:12]}"
>>>>>>> Stashed changes
