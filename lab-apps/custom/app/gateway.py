"""Safety Gateway for the local Inlanefreight lab_api.

All RunTrace and planner requests must use this module. Default-deny, local-host
only, exact method + OpenAPI-template matching, bounded requests, redacted logs.
Never point this at the external HTB host or production.
"""
from __future__ import annotations
import argparse, asyncio, hashlib, json, os, re, threading, time, uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response


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
    request_id: str
    response_body: bytes
    response_headers: dict[str, str]


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
                 rso_path: str | Path = "cyber-range/model/rso.yaml",
                 proxy_url: str | None = None, event_log: str | Path | None = None,
                 profile_id: str = "custom_mock"):

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
        self.proxy_url = proxy_url.rstrip("/") if proxy_url else None
        if self.proxy_url:
            proxy = urlparse(self.proxy_url)
            if proxy.scheme != "http" or proxy.hostname not in permitted:
                raise GatewayDenied("Capture proxy must use local HTTP.")
            self.client.close()
            self.client = httpx.Client(base_url=self.proxy_url, timeout=self.timeout,
                                       follow_redirects=False, trust_env=False)
        self.profile_id = profile_id
        self.event_log = Path(event_log) if event_log else None
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
             params: dict | None = None, json_body: Any = None, content: bytes | None = None,
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
        request_id = safe_headers.get("x-request-id") or str(uuid.uuid4())
        safe_headers.update({
            "x-lab-run-id": run_id, "x-lab-sequence-id": sequence_id,
            "x-request-id": request_id, "x-runtrace-actor": actor,
        })
        if approval:
            safe_headers["x-range-approval"] = "true"
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
            "raw_body_sha256": hashlib.sha256(content).hexdigest() if content is not None else None,
        }
        request_bytes = json.dumps(request_fingerprint, sort_keys=True, separators=(",", ":"), default=str).encode()
        req_hash = hashlib.sha256(request_bytes).hexdigest()
        if self.dry_run:
            return {"dry_run": True, "method": method, "path": path, "allowlist_id": entry["id"],
                    "query_params": params or {}, "request_headers": semantic_headers,
                    "request_sha256": req_hash, "run_id": run_id, "sequence_id": sequence_id}
        start = time.perf_counter()
        with self._request_semaphore:
            response = self.client.request(method, path, params=params, json=json_body,
                                           content=content, headers=safe_headers)
        elapsed = (time.perf_counter() - start) * 1000
        try: payload = response.json()
        except ValueError: payload = {"text": response.text[:2000]}
        response_bytes = response.content
        result = GatewayResult(run_id, sequence_id, actor, method, path, params or None, semantic_headers, response.status_code,
                             round(elapsed, 3), req_hash, hashlib.sha256(response_bytes).hexdigest(),
                             payload, entry["id"], request_id, response_bytes,
                             {k.lower(): v for k, v in response.headers.items()
                              if k.lower() in {"content-type", "location", "content-disposition"}})
        if self.event_log:
            request_payload = json_body
            if request_payload is None and content is not None:
                try:
                    request_payload = json.loads(content)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    request_payload = {"body_omitted": True, "media_type": safe_headers.get("content-type"),
                                       "size_bytes": len(content)}
            event = {"profile_id": self.profile_id, "run_id": run_id, "sequence_id": sequence_id,
                     "workflow_id": safe_headers.get("x-lab-workflow-id"),
                     "step_idx": safe_headers.get("x-lab-step-index"),
                     "case_id": safe_headers.get("x-lab-case-id"),
                     "valid_request": safe_headers.get("x-lab-valid-request"),
                     "operation_id": safe_headers.get("x-lab-operation-id"),
                     "screen": safe_headers.get("x-lab-screen"),
                     "user_action": safe_headers.get("x-lab-user-action"),
                     "object_id": safe_headers.get("x-lab-object-id"),
                     "usecase_step": safe_headers.get("x-lab-usecase-step"),
                     "actor": actor, "method": method, "path": path, "allowlist_id": entry["id"],
                     "request_id": request_id, "request_headers": self.redact(semantic_headers),
                     "request": self.redact(request_payload),
                     "request_body_sha256": (hashlib.sha256(content).hexdigest() if content is not None else
                                             hashlib.sha256(json.dumps(json_body, sort_keys=True, default=str).encode()).hexdigest()
                                             if json_body is not None else None),
                     "status_code": response.status_code, "elapsed_ms": result.elapsed_ms,
                     "response": self.redact(payload), "response_sha256": result.response_sha256,
                     "timestamp": time.time()}
            self.event_log.parent.mkdir(parents=True, exist_ok=True)
            with self._state_lock, self.event_log.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
        return result

    def issue_token(self, actor: str, email: str, password: str,
                    run_id: str | None = None, *, sequence_id: str | None = None,
                    step_idx: int | None = None, workflow_id: str | None = None,
                    interaction: dict | None = None) -> str:
        # Auth bootstrap is also allowlisted and always uses synthetic seed credentials.
        headers = {"x-lab-valid-request": "true"}
        if step_idx is not None:
            headers["x-lab-step-index"] = str(step_idx)
        if workflow_id:
            headers["x-lab-workflow-id"] = workflow_id
        interaction = interaction or {"operation_id": "lab_issue_token", "screen": "Sign in",
                                      "action": "Sign in", "sequence": step_idx}
        for source, target in (("operation_id", "x-lab-operation-id"), ("screen", "x-lab-screen"),
                               ("action", "x-lab-user-action"), ("object_id", "x-lab-object-id"),
                               ("sequence", "x-lab-usecase-step")):
            if interaction.get(source) is not None:
                headers[target] = str(interaction[source])
        result = self.send(actor=actor, method="POST", path="/__lab/auth/token",
                           json_body={"Email": email, "Password": password}, headers=headers,
                           run_id=run_id, sequence_id=sequence_id)
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


def create_proxy_app(*, allowlist: str = "runtrace_allowlist.json",
                     rso: str = "cyber-range/model/rso.yaml",
                     events: str = "runtrace_proxy_events.jsonl",
                     profile_id: str = "custom_mock", upstream_base_url: str | None = None):
    """Create a local reverse-proxy listener; upstream is fixed by the app allowlist."""
    engine = SafetyGateway(allowlist, base_url=upstream_base_url, rso_path=rso,
                           event_log=events, profile_id=profile_id)
    app = FastAPI(title=f"Safety Gateway: {profile_id}", docs_url=None, redoc_url=None)
    app.state.gateway = engine

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    async def proxy(path: str, request: Request):
        peer = request.client.host if request.client else ""
        if peer not in {"127.0.0.1", "::1", "localhost", "testclient"}:
            raise HTTPException(status_code=403, detail="Gateway accepts loopback clients only")
        method, route = request.method, "/" + path
        headers = {k.lower(): v for k, v in request.headers.items()
                   if k.lower() not in {"host", "content-length", "connection", "proxy-connection",
                                        "transfer-encoding", "x-range-approval"}}
        auth = headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else None
        actor = headers.get("x-runtrace-actor", "unknown")
        body = await request.body()
        query = dict(request.query_params) or None
        try:
            result = await asyncio.to_thread(
                engine.send, actor=actor, method=method, path=route, token=token,
                params=query, content=body if body else None, headers=headers,
                run_id=headers.get("x-lab-run-id"), sequence_id=headers.get("x-lab-sequence-id"),
                approval=request.headers.get("x-range-approval", "").lower() == "true")
        except GatewayDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"Upstream unavailable: {type(exc).__name__}") from exc
        return Response(content=result.response_body, status_code=result.status_code,
                        headers=result.response_headers)

    @app.on_event("shutdown")
    def close_gateway():
        engine.close()
    return app


def main():
    parser = argparse.ArgumentParser(description="Run the local app-scoped Safety Gateway proxy")
    parser.add_argument("--serve", action="store_true", help="start the loopback HTTP proxy")
    parser.add_argument("--profile", default="gateway_profile.json", help="app-specific gateway profile JSON")
    parser.add_argument("--allowlist")
    parser.add_argument("--rso")
    parser.add_argument("--events")
    parser.add_argument("--listen-host")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    if not args.serve:
        parser.error("--serve is required")
    profile_path = Path(args.profile)
    if not profile_path.is_absolute() and not profile_path.exists():
        profile_path = Path(__file__).resolve().parent / profile_path
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"Cannot load gateway profile {profile_path}: {exc}")
    allowlist = args.allowlist or profile.get("safety_allowlist", "runtrace_allowlist.json")
    rso = args.rso or profile.get("actor_registry", "cyber-range/model/rso.yaml")
    events = args.events or profile.get("event_log", "runtrace_proxy_events.jsonl")
    listen_host = args.listen_host or profile.get("listen_host", "127.0.0.1")
    port = args.port or int(profile.get("listen_port", 8088))
    if listen_host not in {"127.0.0.1", "::1", "localhost"}:
        parser.error("Gateway listener must bind to loopback")
    import uvicorn
    uvicorn.run(create_proxy_app(allowlist=allowlist, rso=rso,
                                 events=events, profile_id=profile.get("profile_id", profile_path.stem),
                                 upstream_base_url=profile.get("upstream_base_url")),
                host=listen_host, port=port, access_log=False)


if __name__ == "__main__":
    main()
