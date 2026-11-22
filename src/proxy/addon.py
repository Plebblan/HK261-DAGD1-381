"""mitmproxy adapter for the shared OpenAPI-driven Safety Gateway.

SQLite is the canonical, durable audit log. JSONL is exported from that store
when the run closes; the proxy never maintains a parallel event log.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

import yaml

from src.common.types import GatewayRequest, VerdictRecord
from src.gateway.engine import decide
from src.store.store import Store
from src.proxy.har_export import export_har

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _header(headers: Any, name: str, default: str | None = None) -> str | None:
    try:
        value = headers.get(name)
    except AttributeError:
        value = None
    return str(value) if value not in (None, "") else default


def _body_record(raw: bytes, content_type: str | None) -> Any:
    if not raw:
        return None
    if content_type and ("json" in content_type.lower() or "text/" in content_type.lower()):
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            if content_type.lower().startswith("text/"):
                return raw[:8192].decode("utf-8", "replace")
    return {"body_omitted": True, "content_type": content_type, "size_bytes": len(raw)}


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def _redact_query(query: str | None) -> str | None:
    if not query:
        return query
    sensitive = {"token", "access_token", "refresh_token", "password", "secret", "api_key", "key", "code"}
    return urlencode([
        (key, "[REDACTED]" if key.lower() in sensitive else value)
        for key, value in parse_qsl(query, keep_blank_values=True)
    ])




class GatewayAddon:
    """Default-deny proxy adapter with run-scoped durable evidence."""

    def __init__(
        self,
        allowlist: dict[str, Any] | None = None,
        config: dict[str, Any] | None = None,
        *,
        run_dir: str | Path | None = None,
        run_id: str | None = None,
        target_id: str | None = None,
        config_hash: str | None = None,
        openapi_path: str | Path | None = None,
    ):
        self.allowlist = allowlist
        self.config = dict(config or {})
        if os.getenv("RUNTRACE_KILL_SWITCH", "").lower() == "true":
            self.config["kill_switch"] = True
        if os.getenv("RUNTRACE_DRY_RUN", "").lower() == "true":
            self.config["dry_run"] = True
        self.config_hash = config_hash
        self.run_id = run_id or (uuid.uuid4().hex if allowlist is not None else None)
        self.target_id = target_id or str((allowlist or {}).get("target_id", "unknown"))
        self.run_dir = (
            Path(run_dir) if run_dir is not None
            else Path("runs") / self.target_id / str(self.run_id)
        ) if allowlist is not None else None
        self.openapi_path = Path(openapi_path) if openapi_path else None
        self.store: Store | None = None
        self._closed = False
        self._lock = threading.RLock()
        self._request_count = 0
        self._actors_seen: set[str] = set()
        self._active_requests = 0
        self._rate_events: deque[float] = deque()
        self._started_at = _now()
        if allowlist is not None:
            self.run_dir.mkdir(parents=True, exist_ok=True)
            self.store = Store(self.run_dir / "evidence.sqlite3", synchronous="FULL")
            self.store.create_run(
                run_id=self.run_id,
                target=self.target_id,
                mode="runtrace_proxy",
                allowlist_hash=allowlist.get("allowlist_hash"),
                config_hash=config_hash,
                undocumented_policy=allowlist.get("undocumented_policy"),
                isolation_mode=self.config.get("isolation_mode"),
                seed_id=os.getenv("RUNTRACE_SEED_ID"),
                status="running",
                metadata={
                    "trace_path": "trace.jsonl",
                    "run_dir": str(self.run_dir),
                    "openapi_path": str(self.openapi_path) if self.openapi_path else None,
                },
            )
            self._write_run_metadata(status="running")
            (self.run_dir / "allowlist.generated.json").write_text(
                json.dumps(allowlist, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            if self.openapi_path and self.openapi_path.is_file():
                (self.run_dir / "openapi.json").write_bytes(self.openapi_path.read_bytes())

    def _write_run_metadata(self, *, status: str, trace_hash: str | None = None, har_hash: str | None = None) -> None:
        if self.run_dir is None:
            return
        payload = {
            "run_id": self.run_id,
            "target_id": self.target_id,
            "status": status,
            "started_at": self._started_at,
            "finished_at": _now() if status != "running" else None,
            "allowlist_hash": (self.allowlist or {}).get("allowlist_hash"),
            "config_hash": self.config_hash,
            "artifacts": {
                "database": "evidence.sqlite3",
                "trace": "trace.jsonl",
                "har": "trace.har",
                "runtrace": "runtrace.json",
                "allowlist": "allowlist.generated.json",
                "openapi": "openapi.json" if self.openapi_path else None,
            },
            "trace_sha256": trace_hash,
            "har_sha256": har_hash,
        }
        (self.run_dir / "run.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    @classmethod
    def from_files(
        cls,
        allowlist_path: str | Path,
        config_path: str | Path | None = None,
        *,
        run_dir: str | Path | None = None,
        run_id: str | None = None,
        openapi_path: str | Path | None = None,
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
            config_hash = _hash(config_file.read_bytes())
        if not generated.get("allowlist_hash") or not generated.get("target_id"):
            raise ValueError("allowlist is not a generated target-scoped artifact")
        return cls(
            generated, config, run_dir=run_dir, run_id=run_id,
            config_hash=config_hash, openapi_path=openapi_path,
        )

    def load(self, loader: Any) -> None:
        loader.add_option("gateway_allowlist", str, "", "Generated allowlist JSON path")
        loader.add_option("gateway_config", str, "", "Target gateway YAML path")
        loader.add_option("gateway_run_dir", str, "", "Directory for this run's artifacts")
        loader.add_option("gateway_run_id", str, "", "Run ID shared with RunTrace")
        loader.add_option("gateway_openapi", str, "", "Source OpenAPI file copied into run artifacts")

    def configure(self, updated: set[str]) -> None:
        keys = {"gateway_allowlist", "gateway_config", "gateway_run_dir", "gateway_run_id", "gateway_openapi"}
        if not (keys & updated):
            return
        from mitmproxy import ctx
        if not ctx.options.gateway_allowlist:
            raise ValueError("gateway_allowlist must point to a generated allowlist JSON")
        if self.store is not None:
            self.close()
        loaded = type(self).from_files(
            ctx.options.gateway_allowlist,
            ctx.options.gateway_config or None,
            run_dir=ctx.options.gateway_run_dir or None,
            run_id=ctx.options.gateway_run_id or None,
            openapi_path=ctx.options.gateway_openapi or None,
        )
        self.__dict__.update(loaded.__dict__)

    @staticmethod
    def _step_index(headers: Any) -> int | None:
        value = _header(headers, "x-lab-step-index")
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _budget_verdict(self) -> VerdictRecord | None:
        budgets = (self.allowlist or {}).get("budgets", {})
        now = time.monotonic()
        with self._lock:
            self._request_count += 1
            max_requests = int(budgets.get("max_requests_per_run", 0) or 0)
            if max_requests and self._request_count > max_requests:
                return VerdictRecord("blocked", "budget_max_requests_per_run")
            rate = float(budgets.get("rate_per_second", 0) or 0)
            if rate > 0:
                while self._rate_events and now - self._rate_events[0] >= 1.0:
                    self._rate_events.popleft()
                if len(self._rate_events) >= rate:
                    return VerdictRecord("blocked", "budget_rate_per_second")
                self._rate_events.append(now)
            concurrency = int(budgets.get("max_concurrency", 0) or 0)
            if concurrency and self._active_requests >= concurrency:
                return VerdictRecord("blocked", "budget_max_concurrency")
            self._active_requests += 1
        return None

    def _release_request(self, flow: Any) -> None:
        if flow.metadata.get("gateway_active"):
            with self._lock:
                self._active_requests = max(0, self._active_requests - 1)
            flow.metadata["gateway_active"] = False

    def _persist_response(self, event_id: str, response: Any, *, elapsed_ms: float | None) -> None:
        raw = response.raw_content or b""
        content_type = _header(response.headers, "content-type")
        record = _body_record(raw, content_type)
        response_headers = {
            key.lower(): value for key, value in response.headers.items()
            if key.lower() in {"content-type", "location", "content-disposition", "etag", "x-request-id", "x-gateway-verdict", "x-gateway-rule"}
        }
        self.store.append_responses([{
            "event_id": event_id,
            "status": response.status_code,
            "elapsed_ms": elapsed_ms,
            "response_redacted": record,
            "response_hash": _hash(raw),
            "metadata": {"headers": response_headers, "body_bytes": len(raw)},
        }])

    def request(self, flow: Any) -> None:
        """Commit the policy decision before allowing mitmproxy to contact upstream."""
        from mitmproxy import http
        if self.allowlist is None or self.store is None:
            flow.response = http.Response.make(503, b"gateway_not_configured")
            return
        request = flow.request
        raw_path = request.path
        parsed = urlsplit(raw_path)
        path = parsed.path or "/"
        raw_query = parsed.query or None
        query = _redact_query(raw_query)
        host = f"{request.host}:{request.port}"
        headers = request.headers
        actor = _header(headers, "x-runtrace-actor") or _header(headers, "x-stateful-actor")
        run_header = _header(headers, "x-lab-run-id")
        if run_header and run_header != self.run_id:
            flow.response = http.Response.make(409, b"run_id_mismatch")
            return
        raw_body = request.raw_content or b""
        content_type = _header(headers, "content-type")
        request_record = _body_record(raw_body, content_type)
        semantic_headers = {
            key.lower(): value for key, value in headers.items()
            if key.lower() not in {
                "authorization", "cookie", "set-cookie", "x-lab-admin-token", "x-lab-key",
                "x-request-id", "proxy-authorization", "connection", "content-length",
            }
        }
        request_fingerprint = {
            "method": request.method.upper(),
            "host": host.lower(),
            "path": path,
            "query": raw_query,
            "headers": semantic_headers,
            "raw_body_hash": _hash(raw_body) if raw_body else None,
        }
        fingerprint_hash = _hash(json.dumps(
            request_fingerprint, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8"))
        normalized = GatewayRequest(
            method=request.method,
            host=host,
            path=path,
            headers={key.lower(): value for key, value in headers.items()},
            body=raw_body or None,
            actor=actor,
            tags=tuple(filter(None, (_header(headers, "x-lab-tag"),))),
            origin="runtrace",
            run_id=self.run_id,
        )
        budget_verdict = self._budget_verdict()
        flow.metadata["gateway_active"] = budget_verdict is None
        verdict = budget_verdict or decide(
            normalized, allowlist=self.allowlist, config=self.config
        )
        event_id = uuid.uuid4().hex
        request_id = _header(headers, "x-request-id") or uuid.uuid4().hex
        try:
            if actor and actor not in self._actors_seen:
                self.store.record_actor_session(run_id=self.run_id, actor=actor)
                self._actors_seen.add(actor)
            self.store.append_event(
                event_id=event_id,
                run_id=self.run_id,
                ts=_now(),
                workflow_id=_header(headers, "x-lab-workflow-id"),
                sequence_id=_header(headers, "x-lab-sequence-id"),
                step_idx=self._step_index(headers),
                origin="runtrace",
                actor=actor,
                operation_id=_header(headers, "x-lab-operation-id"),
                method=request.method.upper(),
                host=host,
                path=path,
                query=query,
                gateway_verdict=verdict.action,
                gateway_reason=verdict.reason,
                rule_id=verdict.allowlist_rule,
                valid_request=(_header(headers, "x-lab-valid-request", "").lower() == "true")
                    if _header(headers, "x-lab-valid-request") is not None else None,
                request_redacted={"headers": semantic_headers, "body": request_record},
                raw_body_hash=_hash(raw_body) if raw_body else None,
                request_fingerprint=fingerprint_hash,
                before_state_hash=_header(headers, "x-lab-before-state-hash"),
                after_state_hash=_header(headers, "x-lab-after-state-hash"),
                normalized_hash=_header(headers, "x-lab-normalized-hash"),
                normalization_version=_header(headers, "x-lab-normalization-version"),
                source_file=_header(headers, "x-lab-source-file"),
                case_id=_header(headers, "x-lab-case-id"),
                tag=",".join(filter(None, (*verdict.tags, _header(headers, "x-lab-tag")))) or None,
                undocumented="undocumented" in verdict.tags,
                metadata={
                    "request_id": request_id,
                    "target_id": self.target_id,
                    "wf_workflow": _header(headers, "x-lab-wf-workflow"),
                    "wf_action": _header(headers, "x-lab-wf-action"),
                    "guard_object": _header(headers, "x-lab-guard-object"),
                    "field_access": _header(headers, "x-lab-field-access"),
                    "screen": _header(headers, "x-lab-screen"),
                    "user_action": _header(headers, "x-lab-user-action"),
                    "object_id": _header(headers, "x-lab-object-id"),
                    "usecase_step": _header(headers, "x-lab-usecase-step"),
                    "content_type": content_type,
                    "content_length": len(raw_body),
                    "approval_requested": _header(headers, "x-range-approval") == "true",
                },
            )
        except Exception:
            self._release_request(flow)
            logger.exception("gateway audit write failed; blocking request")
            flow.response = http.Response.make(503, b"gateway_audit_unavailable")
            return

        flow.metadata["gateway_event_id"] = event_id
        flow.metadata["gateway_request_id"] = request_id
        flow.metadata["gateway_rule_id"] = verdict.allowlist_rule
        flow.metadata["gateway_verdict"] = verdict.action
        flow.metadata["gateway_started_at"] = time.monotonic()
        logger.info(
            "gateway verdict=%s reason=%s host=%s path=%s run_id=%s event_id=%s",
            verdict.action, verdict.reason, host, path, self.run_id, event_id,
        )
        if verdict.action == "forwarded":
            request.headers["X-Request-Id"] = request_id
            return

        self._release_request(flow)
        status = 200 if verdict.action == "dry_run" else 403
        payload = {
            "gateway_verdict": verdict.action,
            "detail": verdict.reason,
            "reason": verdict.reason,
            "target_id": self.target_id,
            "run_id": self.run_id,
            "event_id": event_id,
        }
        flow.response = http.Response.make(
            status,
            json.dumps(payload).encode("utf-8"),
            {"Content-Type": "application/json", "X-Gateway-Verdict": verdict.action, "X-Gateway-Rule": verdict.allowlist_rule or "", "X-Request-Id": request_id},
        )
        try:
            self._persist_response(event_id, flow.response, elapsed_ms=0.0)
        except Exception:
            logger.exception("gateway response audit write failed; replacing response")
            flow.response = http.Response.make(503, b"gateway_audit_unavailable")

    def response(self, flow: Any) -> None:
        event_id = flow.metadata.get("gateway_event_id")
        if not event_id or flow.response is None or self.store is None:
            self._release_request(flow)
            return
        response = flow.response
        request_id = flow.metadata.get("gateway_request_id")
        if request_id:
            response.headers["X-Request-Id"] = request_id
        response.headers["X-Gateway-Verdict"] = flow.metadata.get("gateway_verdict", "forwarded")
        rule_id = flow.metadata.get("gateway_rule_id")
        if rule_id:
            response.headers["X-Gateway-Rule"] = rule_id
        elapsed = None
        started = flow.metadata.get("gateway_started_at")
        if started is not None:
            elapsed = round((time.monotonic() - started) * 1000, 3)
        try:
            self._persist_response(event_id, flow.response, elapsed_ms=elapsed)
        except Exception:
            logger.exception("gateway response audit write failed for event %s", event_id)
            from mitmproxy import http
            flow.response = http.Response.make(503, b"gateway_audit_unavailable")
        finally:
            self._release_request(flow)

    def error(self, flow: Any) -> None:
        """Persist upstream connection failures against the committed request event."""
        event_id = flow.metadata.get("gateway_event_id")
        if not event_id or self.store is None:
            self._release_request(flow)
            return
        error = getattr(flow, "error", None)
        message = getattr(error, "msg", None) or str(error or "upstream_error")
        try:
            self.store.append_responses([{
                "event_id": event_id,
                "status": 502,
                "response_redacted": {"proxy_error": message[:1000]},
                "metadata": {"transport_error": True},
            }])
        except Exception:
            logger.exception("failed to persist upstream error for event %s", event_id)
        finally:
            self._release_request(flow)

    def export_trace(self) -> Path:
        if self.store is None or self.run_dir is None:
            raise RuntimeError("gateway addon is not configured")
        trace_path = self.run_dir / "trace.jsonl"
        with trace_path.open("w", encoding="utf-8") as stream:
            for event in self.store.get_events(run_id=self.run_id):
                stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True, default=str) + "\n")
        return trace_path

    def done(self) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        if self.store is None:
            self._closed = True
            return
        try:
            trace_path = self.export_trace()
            har_path = export_har(self.store, run_id=self.run_id, path=self.run_dir / "trace.har")
            trace_hash = _hash(trace_path.read_bytes())
            har_hash = _hash(har_path.read_bytes())
            self._write_run_metadata(status="completed", trace_hash=trace_hash, har_hash=har_hash)
            self.store.finish_run(run_id=self.run_id, status="completed", stats={
                "requests_seen": self._request_count,
                "active_at_shutdown": self._active_requests,
                "incomplete_forwarded_events": self.store.count_incomplete_events(run_id=self.run_id),
            })
        except Exception:
            logger.exception("failed to finalize gateway run artifacts")
            try:
                self.store.mark_run_degraded(run_id=self.run_id)
                self._write_run_metadata(status="degraded")
            except Exception:
                logger.exception("failed to mark run degraded")
        finally:
            self.store.close()
            self.store = None
            self._closed = True


def build_addon(
    allowlist_path: str | Path,
    config_path: str | Path | None = None,
    *,
    run_dir: str | Path | None = None,
    run_id: str | None = None,
    openapi_path: str | Path | None = None,
) -> GatewayAddon:
    return GatewayAddon.from_files(
        allowlist_path, config_path, run_dir=run_dir, run_id=run_id,
        openapi_path=openapi_path,
    )


addons = [GatewayAddon()]
