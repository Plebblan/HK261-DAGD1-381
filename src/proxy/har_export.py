"""Export a run's redacted Store events as a HAR 1.2 interchange artifact."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode


def _pairs(value: Any) -> list[dict[str, str]]:
    if not value:
        return []
    if isinstance(value, dict):
        return [{"name": str(k), "value": str(v)} for k, v in value.items()]
    if isinstance(value, str):
        return [{"name": k, "value": v} for k, v in parse_qsl(value, keep_blank_values=True)]
    return []


def _headers(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, dict):
        return []
    return [{"name": str(k), "value": str(v)} for k, v in value.items()]


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    return str(value)


def export_har(store: Any, *, run_id: str, path: str | Path) -> Path:
    """Export redacted request/response records; never reconstruct raw secrets."""
    entries = []
    for event in store.get_events(run_id=run_id):
        metadata = event.get("metadata") or {}
        request = event.get("request_redacted") or {}
        response = event.get("response_redacted")
        request_headers = request.get("headers", {}) if isinstance(request, dict) else {}
        request_body = request.get("body") if isinstance(request, dict) else request
        response_metadata = event.get("response_metadata") or {}
        response_headers = response_metadata.get("headers", {})
        host = event.get("host") or ""
        path_value = event.get("path") or "/"
        query = event.get("query")
        url = f"http://{host}{path_value}"
        if query:
            url += "?" + str(query)
        request_size = int(metadata.get("content_length") or 0)
        response_size = int(response_metadata.get("body_bytes") or 0)
        elapsed = float(event.get("elapsed_ms") or 0)
        entries.append({
            "startedDateTime": event.get("ts") or datetime.now(timezone.utc).isoformat(),
            "time": elapsed,
            "request": {
                "method": event.get("method") or "GET",
                "url": url,
                "httpVersion": "HTTP/1.1",
                "headers": _headers(request_headers),
                "queryString": _pairs(query),
                "cookies": [],
                "headersSize": -1,
                "bodySize": request_size,
                "postData": {
                    "mimeType": metadata.get("content_type") or "application/octet-stream",
                    "text": _text(request_body),
                } if request_body is not None else None,
            },
            "response": {
                "status": int(event.get("status") or 0),
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "headers": _headers(response_headers),
                "cookies": [],
                "content": {
                    "size": response_size,
                    "mimeType": response_metadata.get("headers", {}).get("content-type", "application/octet-stream"),
                    "text": _text(response),
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": response_size,
            },
            "cache": {},
            "timings": {"send": 0, "wait": elapsed, "receive": 0},
            "_eventId": event.get("event_id"),
            "_runId": event.get("run_id"),
            "_actor": event.get("actor"),
            "_workflowId": event.get("workflow_id"),
            "_sequenceId": event.get("sequence_id"),
            "_stepIndex": event.get("step_idx"),
            "_operationId": event.get("operation_id"),
            "_caseId": event.get("case_id"),
            "_fieldAccess": metadata.get("field_access"),
            "_gatewayVerdict": event.get("gateway_verdict"),
            "_gatewayReason": event.get("gateway_reason"),
        })
    document = {
        "log": {
            "version": "1.2",
            "creator": {"name": "HK261 Stateful Safety Gateway", "version": "1.0"},
            "entries": entries,
        }
    }
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output
