"""mitmproxy adapter that sends every outbound flow through the policy engine."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from src.common.types import GatewayRequest
from src.gateway.engine import decide

logger = logging.getLogger(__name__)


class GatewayAddon:
    """Small transport adapter; policy remains in src.gateway.engine."""

    def __init__(self, allowlist: dict[str, Any], config: dict[str, Any] | None = None):
        self.allowlist = allowlist
        self.config = config or {}

    @classmethod
    def from_files(cls, allowlist_path: str | Path, config_path: str | Path | None = None):
        generated = json.loads(Path(allowlist_path).read_text(encoding="utf-8"))
        config = {}
        if config_path is not None:
            loaded = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("gateway config must be a YAML mapping")
            config = loaded
        if not generated.get("allowlist_hash") or not generated.get("target_id"):
            raise ValueError("allowlist is not a generated target-scoped artifact")
        return cls(generated, config)

    def request(self, flow: Any) -> None:
        """mitmproxy request hook; block before upstream forwarding."""
        request = flow.request
        normalized = GatewayRequest(
            method=request.method,
            host=f"{request.host}:{request.port}",
            path=request.path.split("?", 1)[0],
            headers=dict(request.headers.items()),
            body=bytes(request.raw_content or b""),
            actor=request.headers.get("x-stateful-actor"),
            origin="proxy",
            run_id=request.headers.get("x-stateful-run-id"),
        )
        verdict = decide(normalized, allowlist=self.allowlist, config=self.config)
        logger.info("gateway verdict=%s reason=%s host=%s path=%s",
                    verdict.action, verdict.reason, normalized.host, normalized.path)
        if verdict.action == "forwarded":
            return
        from mitmproxy import http
        status = 200 if verdict.action == "dry_run" else 403
        payload = {
            "gateway_verdict": verdict.action,
            "reason": verdict.reason,
            "target_id": self.allowlist.get("target_id"),
        }
        flow.response = http.Response.make(
            status,
            json.dumps(payload).encode("utf-8"),
            {"Content-Type": "application/json", "X-Gateway-Verdict": verdict.action},
        )


def build_addon(allowlist_path: str | Path, config_path: str | Path | None = None) -> GatewayAddon:
    """Load a target-specific allowlist and return the mitmproxy addon."""
    return GatewayAddon.from_files(allowlist_path, config_path)
