"""Small RunTrace HTTP client for the shared reverse-proxy gateway.

This module intentionally contains no allowlist, policy, budget, or audit logic.
Every API request is sent to the local reverse proxy, where src.gateway.engine
makes the decision and src.store persists the evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

import yaml


class GatewayDenied(RuntimeError):
    """The shared proxy denied a RunTrace operation."""


@dataclass
class GatewayResult:
    run_id: str
    sequence_id: str
    actor: str
    method: str
    path: str
    query_params: dict | None
    request_headers: dict[str, str]
    status_code: int
    elapsed_ms: float
    request_sha256: str
    response_sha256: str
    response: Any
    allowlist_id: str | None
    request_id: str
    response_body: bytes
    response_headers: dict[str, str]


class SafetyGateway:
    """Compatibility transport facade; enforcement belongs to the shared proxy."""

    def __init__(
        self,
        allowlist_path: str | Path = "runtrace_allowlist.json",
        base_url: str | None = None,
        *,
        dry_run: bool = False,
        rso_path: str | Path = "cyber-range/model/rso.yaml",
        proxy_url: str | None = None,
        event_log: str | Path | None = None,
        profile_id: str = "runtrace",
        run_id: str | None = None,
        workflow_id: str | None = None,
        target_id: str | None = None,
        timeout: float = 15.0,
    ):
        self.allowlist_path = Path(allowlist_path)
        self.base_url = (base_url or os.getenv("LAB_API_BASE_URL") or "").rstrip("/")
        self.proxy_url = (proxy_url or os.getenv("RUNTRACE_GATEWAY_URL") or "").rstrip("/")
        if not self.proxy_url and not dry_run:
            raise GatewayDenied("RUNTRACE_GATEWAY_URL must point to the shared local reverse proxy.")
        if self.proxy_url:
            parsed_proxy = urlsplit(self.proxy_url)
            if parsed_proxy.scheme != "http" or parsed_proxy.hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise GatewayDenied("RunTrace may connect only to a loopback HTTP gateway listener.")
        self.dry_run = bool(dry_run)
        self.run_id = run_id or os.getenv("RUNTRACE_RUN_ID") or uuid.uuid4().hex
        self.workflow_id = workflow_id or "runtrace"
        self.target_id = target_id or profile_id
        self.timeout = timeout
        self._closed = False
        self.actor_registry: dict[str, dict[str, Any]] = {}
        registry = Path(rso_path)
        if registry.exists():
            raw = registry.read_text(encoding="utf-8")
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = yaml.safe_load(raw) or {}
            if isinstance(data, dict):
                self.actor_registry = {
                    str(row.get("ID")): row for row in data.get("actors", [])
                    if isinstance(row, dict) and row.get("ID") is not None
                }
        self._dry_counter = 0

    @staticmethod
    def redact(value: Any) -> Any:
        secrets = {
            "authorization", "email", "password", "token", "accesstoken",
            "refreshtoken", "secret", "cvv", "otp", "cookie", "set-cookie",
            "x-lab-key", "x-lab-admin-token",
        }
        if isinstance(value, dict):
            return {
                key: "[REDACTED]" if key.lower() in secrets else SafetyGateway.redact(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [SafetyGateway.redact(item) for item in value]
        return value

    def _request(
        self, method: str, path: str, *, actor: str, token: str | None,
        params: dict | None, json_body: Any, content: bytes | None,
        headers: dict | None, run_id: str, sequence_id: str,
        approval: bool, workflow_id: str | None, step_idx: int | None,
    ) -> tuple[int, bytes, dict[str, str], float]:
        if self.dry_run:
            self._dry_counter += 1
            return 200, json.dumps({"dry_run": True, "method": method, "path": path}).encode(), {}, 0.0
        query = urlencode(params or {}, doseq=True)
        url = self.proxy_url + "/" + path.lstrip("/")
        if query:
            url += "?" + query
        outgoing = {str(k): str(v) for k, v in (headers or {}).items()}
        outgoing.update({
            "X-RunTrace-Actor": actor,
            "X-Lab-Run-Id": run_id,
            "X-Lab-Sequence-Id": sequence_id,
            "X-Lab-Workflow-Id": workflow_id or self.workflow_id,
            "X-Lab-Valid-Request": outgoing.get("x-lab-valid-request", "true"),
        })
        if step_idx is not None:
            outgoing["X-Lab-Step-Index"] = str(step_idx)
        if approval:
            outgoing["X-Range-Approval"] = "true"
        if token:
            outgoing["Authorization"] = "Bearer " + token
        data = content if content is not None else (
            json.dumps(json_body, separators=(",", ":"), ensure_ascii=False).encode()
            if json_body is not None else None
        )
        if json_body is not None:
            outgoing.setdefault("Content-Type", "application/json")
        req = Request(url, data=data, headers=outgoing, method=method.upper())
        started = time.perf_counter()
        try:
            response = urlopen(req, timeout=self.timeout)
            status, raw = response.status, response.read()
            response_headers = {k.lower(): v for k, v in response.headers.items()}
        except HTTPError as exc:
            status, raw = exc.code, exc.read()
            response_headers = {k.lower(): v for k, v in exc.headers.items()}
        except URLError as exc:
            raise GatewayDenied(f"Shared gateway unavailable: {exc.reason}") from exc
        elapsed = (time.perf_counter() - started) * 1000
        return status, raw, response_headers, round(elapsed, 3)

    def send(
        self, *, actor: str, method: str, path: str, token: str | None = None,
        params: dict | None = None, json_body: Any = None, content: bytes | None = None,
        headers: dict | None = None, run_id: str | None = None,
        sequence_id: str | None = None, approval: bool = False,
        workflow_id: str | None = None, step_idx: int | None = None,
    ) -> GatewayResult | dict:
        run_id = run_id or self.run_id
        sequence_id = sequence_id or f"{run_id}-sequence-001"
        status, raw, response_headers, elapsed = self._request(
            method, path, actor=actor, token=token, params=params,
            json_body=json_body, content=content, headers=headers,
            run_id=run_id, sequence_id=sequence_id, approval=approval,
            workflow_id=workflow_id, step_idx=step_idx,
        )
        try:
            payload = json.loads(raw) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {"text": raw[:8192].decode("utf-8", "replace")}
        request_material = json.dumps({
            "method": method.upper(), "path": path, "params": params or {},
            "body": self.redact(json_body),
        }, sort_keys=True, separators=(",", ":"), default=str).encode()
        request_hash = hashlib.sha256(request_material).hexdigest()
        response_hash = hashlib.sha256(raw).hexdigest()
        if self.dry_run or response_headers.get("x-gateway-verdict") == "dry_run":
            return {
                "dry_run": True, "method": method.upper(), "path": path,
                "run_id": run_id, "sequence_id": sequence_id,
                "request_sha256": request_hash,
            }
        request_id = response_headers.get("x-request-id", str(uuid.uuid4()))
        return GatewayResult(
            run_id=run_id, sequence_id=sequence_id, actor=actor,
            method=method.upper(), path=path, query_params=params or None,
            request_headers=self.redact(headers or {}), status_code=status,
            elapsed_ms=elapsed, request_sha256=request_hash,
            response_sha256=response_hash, response=payload,
            allowlist_id=response_headers.get("x-gateway-rule"),
            request_id=request_id, response_body=raw,
            response_headers={
                key: value for key, value in response_headers.items()
                if key in {"content-type", "location", "content-disposition", "x-request-id", "x-gateway-verdict", "x-gateway-rule"}
            },
        )

    def issue_token(
        self, actor: str, email: str, password: str, run_id: str | None = None,
        *, sequence_id: str | None = None, step_idx: int | None = None,
        workflow_id: str | None = None, interaction: dict | None = None,
    ) -> str:
        metadata = interaction or {}
        headers = {"X-Lab-Valid-Request": "true"}
        for source, target in (
            ("operation_id", "X-Lab-Operation-Id"), ("screen", "X-Lab-Screen"),
            ("action", "X-Lab-User-Action"), ("object_id", "X-Lab-Object-Id"),
            ("sequence", "X-Lab-Usecase-Step"),
        ):
            if metadata.get(source) is not None:
                headers[target] = str(metadata[source])
        result = self.send(
            actor=actor, method="POST", path="/__lab/auth/token",
            json_body={"Email": email, "Password": password}, headers=headers,
            run_id=run_id, sequence_id=sequence_id, workflow_id=workflow_id,
            step_idx=step_idx,
        )
        if isinstance(result, dict) and result.get("dry_run"):
            return "DRY_RUN_TOKEN"
        if result.status_code >= 400:
            raise GatewayDenied(f"Token endpoint returned {result.status_code}: {result.response}")
        payload = result.response if isinstance(result.response, dict) else {}
        token = payload.get("AccessToken") or payload.get("Token") or payload.get("access_token")
        if not token:
            raise GatewayDenied("Token endpoint did not return a recognized token field.")
        return str(token)

    def close(self) -> None:
        self._closed = True
