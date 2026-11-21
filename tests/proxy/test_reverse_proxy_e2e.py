from __future__ import annotations

import json
import shutil
import socket
import signal
import sqlite3
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from src.proxy.client import SafetyGateway

import pytest
import yaml


class TargetHandler(BaseHTTPRequestHandler):
    calls = 0

    def do_GET(self):
        type(self).calls += 1
        body = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.skipif(shutil.which("mitmdump") is None, reason="mitmdump is not installed")
def test_real_reverse_proxy_records_forwarded_and_blocked_runtrace_events(tmp_path):
    TargetHandler.calls = 0
    target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    target_port = target.server_address[1]
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()

    proxy_port = free_port()
    run_id = "real-proxy-e2e"
    run_dir = tmp_path / "runs" / "e2e" / run_id
    run_dir.mkdir(parents=True)
    host = f"127.0.0.1:{target_port}"
    allowlist = {
        "target_id": "e2e",
        "allowlist_hash": "e2e-hash",
        "scope": {"in_scope_hosts": [host], "pass_hosts": []},
        "undocumented_policy": "block",
        "approved_patterns": [{"method": "*", "path": "*"}],
        "entries": [
            {"id": "health", "method": "GET", "path": "/health",
             "allow": True, "destructiveness": "read", "tags": ["read"]},
        ],
        "budgets": {"max_requests_per_run": 10, "rate_per_second": 10, "max_concurrency": 2},
    }
    allowlist_path = run_dir / "allowlist.generated.json"
    allowlist_path.write_text(json.dumps(allowlist), encoding="utf-8")
    config_path = run_dir / "gateway.yaml"
    config_path.write_text(yaml.safe_dump({
        "target": {"base_url": f"http://127.0.0.1:{target_port}"},
        "dry_run": False,
    }), encoding="utf-8")

    command = [
        "mitmdump", "--mode", f"reverse:http://127.0.0.1:{target_port}",
        "--listen-host", "127.0.0.1", "--listen-port", str(proxy_port),
        "-s", str(Path(__file__).resolve().parents[2] / "src" / "proxy" / "addon.py"),
        "--set", f"gateway_allowlist={allowlist_path}",
        "--set", f"gateway_config={config_path}",
        "--set", f"gateway_run_dir={run_dir}",
        "--set", f"gateway_run_id={run_id}",
    ]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(f"mitmdump exited early with code {process.returncode}")
            try:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("mitmdump did not open its listener")
        time.sleep(0.5)

        client = SafetyGateway(proxy_url=proxy_url, run_id=run_id, workflow_id="workflow-e2e")
        try:
            forwarded = client.send(
                actor="actor-e2e", method="GET", path="/health",
                params={"access_token": "do-not-log-this"},
                run_id=run_id, sequence_id="sequence-e2e",
                workflow_id="workflow-e2e", step_idx=1,
            )
            assert forwarded.status_code == 200
            assert forwarded.response["ok"] is True
            assert forwarded.response_headers["x-gateway-verdict"] == "forwarded"
            assert forwarded.request_id

            blocked = client.send(
                actor="actor-e2e", method="GET", path="/not-allowlisted",
                run_id=run_id, sequence_id="sequence-e2e",
                workflow_id="workflow-e2e", step_idx=2,
            )
            assert blocked.status_code == 403
            assert blocked.response["gateway_verdict"] == "blocked"
            assert blocked.response_headers["x-gateway-verdict"] == "blocked"
        finally:
            client.close()
        assert TargetHandler.calls == 1
    finally:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        target.shutdown()
        target.server_close()
        target_thread.join(timeout=2)

    trace = [json.loads(line) for line in (run_dir / "trace.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [event["gateway_verdict"] for event in trace] == ["forwarded", "blocked"]
    assert "do-not-log-this" not in (run_dir / "trace.jsonl").read_text(encoding="utf-8")
    assert trace[0]["query"] == "access_token=%5BREDACTED%5D"
    assert all(event["run_id"] == run_id for event in trace)
    assert (run_dir / "trace.har").is_file()
    meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert meta["status"] == "completed"
    connection = sqlite3.connect(run_dir / "evidence.sqlite3")
    rows = connection.execute(
        "SELECT event_id, gateway_verdict FROM events WHERE run_id=? ORDER BY rowid",
        (run_id,),
    ).fetchall()
    connection.close()
    assert [row[0] for row in rows] == [event["event_id"] for event in trace]
    assert [row[1] for row in rows] == ["forwarded", "blocked"]
    connection = sqlite3.connect(run_dir / "evidence.sqlite3")
    metadata = json.loads(connection.execute(
        "SELECT metadata FROM events WHERE event_id=?", (trace[0]["event_id"],)
    ).fetchone()[0])
    connection.close()
    assert metadata["request_id"] == forwarded.request_id
