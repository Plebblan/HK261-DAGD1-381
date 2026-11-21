from __future__ import annotations

import json
import sqlite3
import sys
import types
from pathlib import Path
from types import SimpleNamespace

from src.proxy.addon import GatewayAddon


class FakeResponse:
    def __init__(self, status_code: int, content: bytes, headers=None):
        self.status_code = status_code
        self.raw_content = content
        self.headers = headers or {}

    @classmethod
    def make(cls, status_code, content, headers=None):
        return cls(status_code, content, headers)


def install_fake_mitmproxy(monkeypatch):
    package = types.ModuleType("mitmproxy")
    package.http = SimpleNamespace(Response=FakeResponse)
    monkeypatch.setitem(sys.modules, "mitmproxy", package)


def make_flow(method: str, path: str):
    request = SimpleNamespace(
        method=method,
        host="127.0.0.1",
        port=8001,
        path=path,
        headers={"x-stateful-actor": "trace-test"},
        raw_content=b"",
    )
    return SimpleNamespace(request=request, metadata={}, response=None)


def test_gateway_records_forwarded_and_blocked_events_in_run_trace(tmp_path, monkeypatch):
    install_fake_mitmproxy(monkeypatch)
    run_id = "integration-trace-run"
    run_dir = tmp_path / "runs" / "tenantdesk" / run_id
    allowlist = {
        "target_id": "tenantdesk",
        "allowlist_hash": "test-hash",
        "scope": {"in_scope_hosts": ["127.0.0.1:8001"], "pass_hosts": []},
        "undocumented_policy": "block",
        "entries": [
            {"id": "health", "method": "GET", "path": "/_lab/health",
             "allow": True, "destructiveness": "read", "tags": ["read"]},
        ],
    }
    addon = GatewayAddon(allowlist, run_dir=run_dir, run_id=run_id)

    allowed = make_flow("GET", "/_lab/health")
    addon.request(allowed)
    assert allowed.response is None
    allowed.response = FakeResponse(200, b'{"ok":true}')
    addon.response(allowed)

    blocked = make_flow("DELETE", "/_lab/health")
    addon.request(blocked)
    assert blocked.response.status_code == 403
    addon.close()

    trace_path = run_dir / "trace.jsonl"
    trace = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()]
    assert [event["gateway_verdict"] for event in trace] == ["forwarded", "blocked"]
    assert all(event["run_id"] == run_id for event in trace)
    assert (run_dir / "run.json").is_file()
    assert (run_dir / "allowlist.generated.json").is_file()
    assert (run_dir / "evidence.sqlite3").is_file()

    connection = sqlite3.connect(run_dir / "evidence.sqlite3")
    rows = connection.execute(
        "SELECT event_id, run_id, gateway_verdict FROM events ORDER BY rowid"
    ).fetchall()
    response_count = connection.execute(
        "SELECT COUNT(*) FROM event_responses"
    ).fetchone()[0]
    connection.close()

    assert [row[0] for row in rows] == [event["event_id"] for event in trace]
    assert all(row[1] == run_id for row in rows)
    assert [row[2] for row in rows] == [event["gateway_verdict"] for event in trace]
    assert response_count == 2
