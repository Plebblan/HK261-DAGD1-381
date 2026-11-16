"""Interchange helpers. Database access remains behind :class:`Store`."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .store import Store


def export_jsonl(rows: Iterable[dict[str, Any]], *, path: str | Path) -> None:
    """Write rows as newline-delimited JSON."""
    with Path(path).open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":"), default=str) + "\n")


def export_run_jsonl(store: Store, *, run_id: str, path: str | Path, **filters: Any) -> None:
    export_jsonl(store.get_events(run_id=run_id, **filters), path=path)


def import_jsonl(store: Store, *, path: str | Path, actor: str | None = None, source_file: str | None = None) -> int:
    """Import event records idempotently as historical (never forwarded) events."""
    source = str(source_file or Path(path).resolve())
    batch: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {line_number}") from exc
            event = row.get("event", row)
            if not isinstance(event, dict) or not event.get("event_id") or not event.get("run_id"):
                raise ValueError(f"line {line_number} must include event_id and run_id")
            event = dict(event)
            event["origin"] = "import"
            event["gateway_verdict"] = "imported"
            event["actor"] = actor if actor is not None else event.get("actor")
            event["source_file"] = source
            batch.append(event)
    if batch:
        store.append_events(batch)
    return len(batch)


def export_har(store: Store, *, run_id: str, path: str | Path, **filters: Any) -> None:
    """Export stored events in a basic HAR 1.2 shape, preserving trace metadata."""
    entries = []
    for event in store.get_events(run_id=run_id, **filters):
        request = event.get("request_redacted") or {}
        response = event.get("response_redacted") or {}
        headers = request.get("headers", []) if isinstance(request, dict) else []
        response_headers = response.get("headers", []) if isinstance(response, dict) else []
        entries.append({
            "startedDateTime": event.get("ts") or datetime.now(timezone.utc).isoformat(),
            "time": 0,
            "request": {
                "method": event.get("method") or "GET",
                "url": _url(event),
                "httpVersion": "HTTP/1.1",
                "headers": _har_headers(headers),
                "queryString": _query(event.get("query")),
                "headersSize": -1,
                "bodySize": -1,
                "postData": {"mimeType": "application/json", "text": json.dumps(request.get("body"), default=str)} if isinstance(request, dict) and "body" in request else None,
            },
            "response": {
                "status": event.get("status") or 0,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "headers": _har_headers(response_headers),
                "content": {"size": -1, "mimeType": "application/json", "text": json.dumps(response.get("body"), default=str) if isinstance(response, dict) and "body" in response else ""},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": -1,
            },
            "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0},
            "_actor": event.get("actor"), "_fieldAccess": event.get("metadata", {}).get("field_access"),
            "_eventId": event.get("event_id"), "_gatewayVerdict": event.get("gateway_verdict"),
        })
    document = {"log": {"version": "1.2", "creator": {"name": "HK261-DAGD1-381", "version": "0.1"}, "entries": entries}}
    Path(path).write_text(json.dumps(document, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def _url(event: dict[str, Any]) -> str:
    scheme = event.get("metadata", {}).get("scheme", "https")
    host = event.get("host") or ""
    path = event.get("path") or "/"
    query = event.get("query")
    return f"{scheme}://{host}{path}" + (f"?{query}" if query else "")


def _query(value: str | None) -> list[dict[str, str]]:
    if not value:
        return []
    from urllib.parse import parse_qsl
    return [{"name": key, "value": item} for key, item in parse_qsl(value, keep_blank_values=True)]


def _har_headers(value: Any) -> list[dict[str, str]]:
    if isinstance(value, dict):
        return [{"name": str(key), "value": str(item)} for key, item in value.items()]
    if isinstance(value, list):
        return [dict(name=str(item.get("name", "")), value=str(item.get("value", ""))) for item in value if isinstance(item, dict)]
    return []
