"""Safety Gateway for the local Inlanefreight lab_api.

All RunTrace and planner requests must use this module. Default-deny, local-host
only, exact method + OpenAPI-template matching, bounded requests, redacted logs.
Never point this at the external HTB host or production.
"""
from __future__ import annotations
import hashlib, json, os, re, threading, time, uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx


class GatewayDenied(RuntimeError): pass


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
    allowlist_id: str


def _canonical_path(path: str) -> str:
    path = "/" + path.strip("/")
    return path if path == "/" else path


def _template_match(template: str, actual: str) -> bool:
    # Convert OpenAPI {param} segments to one non-slash segment.
    rx = re.sub(r"\{[^/{}]+\}", r"[^/]+", _canonical_path(template))
    return re.fullmatch(rx.rstrip("/") + r"/?", _canonical_path(actual)) is not None


class SafetyGateway:
    def __init__(self, allowlist_path: str | Path = "runtrace_allowlist.json",
                 base_url: str | None = None, *, dry_run: bool = False,
                 rso_path: str | Path = "cyber-range/model/rso.yaml"):

        module_dir = Path(__file__).resolve().parent
        allowlist_file = Path(allowlist_path)
        if not allowlist_file.is_absolute() and not allowlist_file.exists():
            allowlist_file = module_dir / allowlist_file
        self.config = json.loads(allowlist_file.read_text(encoding="utf-8"))
        target = self.config["target"]
        self.base_url = (base_url or os.getenv("LAB_API_BASE_URL") or target["base_url"]).rstrip("/")
        parsed = urlparse(self.base_url)
        permitted = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "http" or parsed.hostname not in permitted:
            raise GatewayDenied("Only local HTTP lab targets are permitted.")
        if parsed.port != int(target.get("port", 8000)):
            raise GatewayDenied("Target port does not match allowlist.")
        self.dry_run = dry_run or os.getenv("RUNTRACE_DRY_RUN", "false").lower() == "true"
        self.kill_switch = os.getenv("RUNTRACE_KILL_SWITCH", "false").lower() == "true"
        limits = self.config.get("global_limits", {})
        self.max_requests = int(limits.get("max_requests_per_run", limits.get("max_requests_per_sequence", 40)))
        self.timeout = float(self.config.get("global_limits", {}).get("timeout_seconds", 10))
        self.counts = defaultdict(int)
        self.minute_events = defaultdict(deque)
        self._state_lock = threading.Lock()
        self._request_semaphore = threading.BoundedSemaphore(max(1, int(limits.get("max_concurrency", 1))))
        self.client = httpx.Client(base_url=self.base_url, timeout=self.timeout,
                                   follow_redirects=False, trust_env=False)
        self.entries = self.config.get("entries", [])
        # RSO supplies synthetic identities only. Never load vulnerability_flags/planted labels.
        self.actor_registry: dict[str, dict] = {}
        registry_path = Path(rso_path)
        if not registry_path.is_absolute() and not registry_path.exists():
            registry_path = module_dir / registry_path
        if registry_path.exists():
            try:
                registry = json.loads(registry_path.read_text(encoding="utf-8"))
                self.actor_registry = {str(row.get("ID")): row for row in registry.get("actors", [])}
            except (json.JSONDecodeError, OSError) as exc:
                raise GatewayDenied(f"Cannot load RSO actor registry: {exc}") from exc

    def close(self): self.client.close()

    def _entry(self, method: str, path: str) -> dict:
        for entry in self.entries:
            if entry.get("allow") and entry.get("method", "").upper() == method.upper() and _template_match(entry["path"], path):
                return entry
        raise GatewayDenied(f"Not allowlisted: {method.upper()} {path}")

    def send(self, *, actor: str, method: str, path: str, token: str | None = None,
             params: dict | None = None, json_body: Any = None,
             headers: dict | None = None, run_id: str | None = None,
             sequence_id: str | None = None, approval: bool = False) -> GatewayResult | dict:
        if self.kill_switch: raise GatewayDenied("Kill switch is active.")
        method, path = method.upper(), _canonical_path(path)
        entry = self._entry(method, path)
        run_id, sequence_id = run_id or str(uuid.uuid4()), sequence_id or str(uuid.uuid4())
        with self._state_lock:
            self.counts[run_id] += 1
            if self.counts[run_id] > self.max_requests:
                raise GatewayDenied("Per-run request budget exceeded.")
        if entry.get("execution_mode") == "approval_required" and not approval:
            raise GatewayDenied(f"Manual approval required for {entry['id']}.")
        if entry.get("auth_required", True) and not token:
            raise GatewayDenied("Authenticated operation requires actor token.")
        now = time.monotonic()
        limit = int(entry.get("rate_limit_per_minute", 10))
        bucket_key = entry["id"]
        with self._state_lock:
            bucket = self.minute_events[bucket_key]
            while bucket and now - bucket[0] > 60: bucket.popleft()
            if len(bucket) >= limit:
                raise GatewayDenied("Per-operation rate limit exceeded.")
            bucket.append(now)

        safe_headers = dict(headers or {})
        safe_headers.update({
            "x-lab-run-id": run_id, "x-lab-sequence-id": sequence_id,
            "x-request-id": str(uuid.uuid4()), "x-runtrace-actor": actor,
        })
        if token: safe_headers["Authorization"] = f"Bearer {token}"
        volatile_or_secret_headers = {
            "authorization", "cookie", "set-cookie", "x-lab-admin-token",
            "x-request-id", "x-lab-run-id", "x-lab-sequence-id",
        }
        semantic_headers = {
            key.lower(): value for key, value in safe_headers.items()
            if key.lower() not in volatile_or_secret_headers
        }
        request_fingerprint = {
            "method": method,
            "path": path,
            "query_params": params or {},
            "headers": semantic_headers,
            "json_body": json_body,
        }
        request_bytes = json.dumps(request_fingerprint, sort_keys=True, separators=(",", ":"), default=str).encode()
        req_hash = hashlib.sha256(request_bytes).hexdigest()
        if self.dry_run:
            return {"dry_run": True, "method": method, "path": path, "allowlist_id": entry["id"],
                    "query_params": params or {}, "request_headers": semantic_headers,
                    "request_sha256": req_hash, "run_id": run_id, "sequence_id": sequence_id}
        start = time.perf_counter()
        with self._request_semaphore:
            response = self.client.request(method, path, params=params, json=json_body, headers=safe_headers)
        elapsed = (time.perf_counter() - start) * 1000
        try: payload = response.json()
        except ValueError: payload = {"text": response.text[:2000]}
        response_bytes = response.content
        return GatewayResult(run_id, sequence_id, actor, method, path, params or None, semantic_headers, response.status_code,
                             round(elapsed, 3), req_hash, hashlib.sha256(response_bytes).hexdigest(),
                             payload, entry["id"])

    def issue_token(self, actor: str, email: str, password: str,
                    run_id: str | None = None) -> str:
        # Auth bootstrap is also allowlisted and always uses synthetic seed credentials.
        result = self.send(actor=actor, method="POST", path="/__lab/auth/token",
                           json_body={"Email": email, "Password": password}, run_id=run_id)
        if isinstance(result, dict): raise GatewayDenied("Cannot issue token in dry-run mode.")
        if result.status_code >= 400: raise GatewayDenied(f"Token endpoint returned {result.status_code}: {result.response}")
        token = result.response.get("AccessToken") or result.response.get("Token") or result.response.get("access_token")
        if not token: raise GatewayDenied("Token response did not contain a recognized token field.")
        return str(token)

    @staticmethod
    def redact(value: Any) -> Any:
        secrets = {"authorization", "email", "password", "token", "accesstoken", "refreshtoken",
                   "secret", "cvv", "otp", "cookie", "set-cookie"}
        if isinstance(value, dict):
            return {k: ("[REDACTED]" if k.lower() in secrets else SafetyGateway.redact(v))
                    for k, v in value.items()}
        if isinstance(value, list): return [SafetyGateway.redact(v) for v in value]
        return value
