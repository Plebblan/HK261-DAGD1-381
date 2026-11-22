"""custom_1 target configs are enforced by the shared OpenAPI policy engine."""
from pathlib import Path

import yaml

from src.allowlist.builder import build_allowlist
from src.common.types import GatewayRequest
from src.gateway.engine import decide

ROOT = Path(__file__).resolve().parents[1]


def target_allowlist(app: str):
    config = yaml.safe_load((ROOT / "config" / app / "gateway.yaml").read_text(encoding="utf-8"))
    spec = {
        "operations": [
            {"operation_id": "login", "method": "POST", "route_template": "/auth/login"},
            {"operation_id": "list_tickets", "method": "GET", "route_template": "/tickets"},
            {"operation_id": "get_ticket", "method": "GET", "route_template": "/tickets/{ticket_id}"},
            {"operation_id": "delete_ticket", "method": "DELETE", "route_template": "/tickets/{ticket_id}"},
        ]
    }
    return config, build_allowlist(spec, config)


def req(method, path, host, *, actor="actor-test", approval=False):
    headers = {"x-range-approval": "true"} if approval else {}
    return GatewayRequest(method=method, path=path, host=host, actor=actor, headers=headers)


def test_tenantdesk_allows_documented_read_and_login_bootstrap():
    config, allowlist = target_allowlist("tenantdesk")
    host = "127.0.0.1:8001"
    assert decide(req("GET", "/tickets/1001", host), allowlist=allowlist, config=config).action == "forwarded"
    assert decide(req("POST", "/auth/login", host), allowlist=allowlist, config=config).action == "forwarded"


def test_documented_write_requires_explicit_per_request_approval():
    config, allowlist = target_allowlist("tenantdesk")
    host = "127.0.0.1:8001"
    blocked = decide(req("DELETE", "/tickets/1001", host), allowlist=allowlist, config=config)
    assert blocked.action == "blocked"
    assert blocked.reason == "write_requires_approval"
    approved = decide(req("DELETE", "/tickets/1001", host, approval=True), allowlist=allowlist, config=config)
    assert approved.action == "forwarded"


def test_reset_is_explicit_extra_method_and_requires_approval():
    config, allowlist = target_allowlist("tenantdesk")
    host = "127.0.0.1:8001"
    assert decide(req("POST", "/_lab/reset", host), allowlist=allowlist, config=config).action == "blocked"
    approved = decide(req("POST", "/_lab/reset", host, actor="lab-control", approval=True),
                      allowlist=allowlist, config=config)
    assert approved.action == "forwarded"


def test_undocumented_and_out_of_scope_requests_remain_default_denied():
    config, allowlist = target_allowlist("shopflow")
    assert decide(req("GET", "/not-documented", "127.0.0.1:8002"), allowlist=allowlist, config=config).reason == "undocumented_operation"
    assert decide(req("GET", "/orders", "127.0.0.1:8001"), allowlist=allowlist, config=config).reason == "out_of_scope_host"


def test_kill_switch_blocks_documented_read():
    config, allowlist = target_allowlist("shopflow")
    verdict = decide(req("GET", "/tickets", "127.0.0.1:8002"),
                     allowlist=allowlist, config={**config, "kill_switch": True})
    assert verdict.action == "blocked"
    assert verdict.reason == "kill_switch"
