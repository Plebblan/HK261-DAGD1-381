"""mitmproxy adapter with run-scoped, durable gateway trace recording."""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from src.common.types import GatewayRequest
from src.gateway.engine import decide
from src.store.store import Store

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class GatewayAddon:
    """Transport adapter; every decision is committed before a request can pass."""

    def __init__(
        self,
        allowlist: dict[str, Any] | None = None,
        config: dict[str, Any] | None = None,
        *,
        run_dir: str | Path | None = None,
        run_id: str | None = None,
        target_id: str | None = None,
        config_hash: str | None = None,
    ):
        self.allowlist = allowlist
        self.config = config or {}
        self.config_hash = config_hash
        self.run_id = run_id or uuid.uuid4().hex
        self.target_id = target_id or str((allowlist or {}).get("target_id", "unknown"))
        self.run_dir = Path(run_dir) if run_dir is not None else Path("runs") / self.target_id / self.run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(self.run_dir / "evidence.sqlite3")
        self.store.create_run(
            run_id=self.run_id,
            target=self.target_id,
            mode="proxy",
            allowlist_hash=(allowlist or {}).get("allowlist_hash"),
            config_hash=config_hash,
            undocumented_policy=(allowlist or {}).get("undocumented_policy"),
            status="running",
            metadata={"trace_path": "trace.jsonl", "run_dir": str(self.run_dir)},
        )
        self._closed = False
        self._export_run_metadata()

    def _export_run_metadata(self) -> None:
        payload = {
            "run_id": self.run_id,
            "target_id": self.target_id,
            "started_at": _now(),
            "allowlist_hash": (self.allowlist or {}).get("allowlist_hash"),
            "config_hash": self._config_hash,
            "artifacts": {
                "database": "evidence.sqlite3",
                "trace": "trace.jsonl",
                "allowlist": "allowlist.generated.json",
            },
        }
        (self.run_dir / "run.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\\n",
            encoding="utf-8",
        )
        if self.allowlist is not None:
            (self.run_dir / "allowlist.generated.json").write_text(
                json.dumps(self.allowlist, ensure_ascii=False, indent=2, sort_keys=True) + "\\n",
                encoding="utf-8",
            )

    @property
    def _config_hash(self) -> str | None:
        return getattr(self, "config_hash", None)

    @classmethod
    def from_files(
        cls,
        allowlist_path: str | Path,
        config_path: str | Path | None = None,
        *,
        run_dir: str | Path | None = None,
        run_id: str | None = None,
    ) -> "GatewayAddon":
        allowlist_file = Path(allowlist_path)
        generated = json.loads(allowlist_file.read_text(encoding="utf-8"))
        config: dict[str, Any] = {}
        config_hash = None
        if config_path is not None:
            config_file = Path(config_path)
            loaded = yaml.safe_load(config_file.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("gateway config must be a YAML mapping")
            config = loaded
            config_hash = hashlib.sha256(config_file.read_bytes()).hexdigest()
        if not generated.get("allowlist_hash") or not generated.get("target_id"):
            raise ValueError("allowlist is not a generated target-scoped artifact")
        instance = cls(
            generated, config, run_dir=run_dir, run_id=run_id,
            config_hash=config_hash,
        )
        return instance

    def load(self, loader: Any) -> None:
        """Register mitmproxy options when loaded as a script addon."""
        from mitmproxy import ctx
        loader.add_option("gateway_allowlist", str, "", "Generated allowlist JSON path")
        loader.add_option("gateway_config", str, "", "Target gateway YAML path")
        loader.add_option("gateway_run_dir", str, "", "Directory for this run's artifacts")
        loader.add_option("gateway_run_id", str, "", "Stable run ID (generated when omitted)")

    def configure(self, updated: set[str]) -> None:
        if not ({"gateway_allowlist", "gateway_config", "gateway_run_dir", "gateway_run_id"} & updated):
            return
        from mitmproxy import ctx
        if not ctx.options.gateway_allowlist:
            raise ValueError("set --set gateway_allowlist=/path/to/allowlist.generated.json")
        if self.store is not None:
            self.close()
        loaded = type(self).from_files(
            ctx.options.gateway_allowlist,
            ctx.options.gateway_config or None,
            run_dir=ctx.options.gateway_run_dir or None,
            run_id=ctx.options.gateway_run_id or None,
        )
        self.__dict__.update(loaded.__dict__)

    def request(self, flow: Any) -> None:
        """Commit the request and verdict before mitmproxy may contact upstream."""
        if self.allowlist is None:
            from mitmproxy import http
            flow.response = http.Response.make(503, b"gateway_not_configured")
            return
        request = flow.request
        url_path = request.path.split("?", 1)[0]
        query = request.path.split("?", 1)[1] if "?" in request.path else None
        normalized = GatewayRequest(
            method=request.method,
            host=f"{request.host}:{request.port}",
            path=url_path,
            headers={},
            body=None,
            actor=request.headers.get("x-stateful-actor"),
            origin="proxy",
            run_id=self.run_id,
        )
        verdict = decide(normalized, allowlist=self.allowlist, config=self.config)
        event_id = uuid.uuid4().hex
        flow.metadata["gateway_event_id"] = event_id
        event = {
            "event_id": event_id,
            "run_id": self.run_id,
            "ts": _now(),
            "origin": "proxy",
            "actor": normalized.actor,
            "method": normalized.method,
            "host": normalized.host,
            "path": normalized.path,
            "query": query,
            "gateway_verdict": verdict.action,
            "gateway_reason": verdict.reason,
            "rule_id": verdict.allowlist_rule,
            "tag": ",".join(verdict.tags) or None,
            "undocumented": "undocumented" in verdict.tags,
            "metadata": {"target_id": self.target_id},
        }
        try:
            # Store.append_event returns only after SQLite commits. Fail closed below.
            self.store.append_event(**event)
        except Exception:
            logger.exception("gateway audit write failed; blocking request")
            from mitmproxy import http
            flow.response = http.Response.make(503, b"gateway_audit_unavailable")
            return

        logger.info(
            "gateway verdict=%s reason=%s host=%s path=%s run_id=%s",
            verdict.action, verdict.reason, normalized.host, normalized.path, self.run_id,
        )
        if verdict.action == "forwarded":
            return
        from mitmproxy import http
        status = 200 if verdict.action == "dry_run" else 403
        payload = {
            "gateway_verdict": verdict.action,
            "reason": verdict.reason,
            "target_id": self.target_id,
            "run_id": self.run_id,
            "event_id": event_id,
        }
        flow.response = http.Response.make(
            status,
            json.dumps(payload).encode("utf-8"),
            {"Content-Type": "application/json", "X-Gateway-Verdict": verdict.action},
        )
        # For gateway-generated responses there is no upstream response hook.
        self.store.append_responses([{
            "event_id": event_id,
            "status": status,
            "response_redacted": payload,
        }])

    def response(self, flow: Any) -> None:
        """Commit upstream response metadata for a previously committed request."""
        event_id = flow.metadata.get("gateway_event_id")
        if not event_id or flow.response is None:
            return
        response = flow.response
        try:
            self.store.append_responses([{
                "event_id": event_id,
                "status": response.status_code,
                "response_redacted": {
                    "headers": {},
                    "body_bytes": len(response.raw_content or b""),
                },
            }])
        except Exception:
            logger.exception("gateway response audit write failed for event %s", event_id)

    def export_trace(self) -> Path:
        """Export the canonical SQLite event stream as run-local JSONL."""
        trace_path = self.run_dir / "trace.jsonl"
        with trace_path.open("w", encoding="utf-8") as stream:
            for event in self.store.get_events(run_id=self.run_id):
                stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True, default=str) + "\\n")
        return trace_path

    def done(self) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.export_trace()
        finally:
            self.store.close()
            self._closed = True


def build_addon(
    allowlist_path: str | Path,
    config_path: str | Path | None = None,
    *,
    run_dir: str | Path | None = None,
    run_id: str | None = None,
) -> GatewayAddon:
    """Load a target-specific allowlist and create a run-scoped addon."""
    return GatewayAddon.from_files(
        allowlist_path, config_path, run_dir=run_dir, run_id=run_id,
    )


# mitmdump -s src/proxy/addon.py --set gateway_allowlist=... --set gateway_run_dir=...
addons = [GatewayAddon()]
