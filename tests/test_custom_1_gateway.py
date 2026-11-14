"""custom_1 Safety Gateway profiles: the existing engine (lab-apps/custom/app/gateway.py) must enforce the custom_1 allowlists.

All tests use dry-run or never reach the network. Run from the repository root:  pytest tests
"""
import importlib.util
import sys
from pathlib import Path

import pytest

LAB_APPS = Path(__file__).resolve().parents[1] / "lab-apps"
GW_DIR = LAB_APPS / "custom_1" / "cyber-range" / "gateway"
sys.path.insert(0, str(LAB_APPS / "custom" / "app"))
import gateway  # noqa: E402  the existing engine, unmodified

TOKEN = "tok_dummy"


@pytest.fixture
def td(monkeypatch):
    monkeypatch.delenv("RUNTRACE_KILL_SWITCH", raising=False)
    g = gateway.SafetyGateway(GW_DIR / "tenantdesk_allowlist.json", base_url="http://localhost:8001", dry_run=True,
                              rso_path=LAB_APPS / "custom_1/cyber-range/model/rso_custom.yaml", profile_id="custom_1_tenantdesk")
    yield g
    g.close()


def send(g, method, path, **kw):
    return g.send(actor="actor-amy", method=method, path=path, token=kw.pop("token", TOKEN), **kw)


def test_allowlisted_request_is_forwarded_in_dry_run(td):
    r = send(td, "GET", "/tickets/1001", run_id="r1")
    assert r["dry_run"] is True and r["allowlist_id"] == "get_ticket"


@pytest.mark.parametrize("method,path", [("GET", "/docs"), ("GET", "/openapi.json"), ("GET", "/nope"), ("PUT", "/tickets/1001"),
                                          ("GET", "/users/1/extra"), ("POST", "/_lab/seed")])
def test_everything_else_is_default_denied(td, method, path):
    with pytest.raises(gateway.GatewayDenied, match="Not allowlisted"):
        send(td, method, path)


def test_authenticated_operation_needs_a_token(td):
    with pytest.raises(gateway.GatewayDenied, match="requires actor token"):
        send(td, "GET", "/tickets/1001", token=None)


def test_login_does_not_need_a_token(td):
    assert send(td, "POST", "/auth/login", token=None, json_body={"username": "amy", "password": "x"})["allowlist_id"] == "login"


@pytest.mark.parametrize("method,path", [("DELETE", "/users/4"), ("DELETE", "/documents/2001"), ("DELETE", "/tickets/1001"), ("POST", "/_lab/reset")])
def test_destructive_operations_need_explicit_approval(td, method, path):
    with pytest.raises(gateway.GatewayDenied, match="Manual approval required"):
        send(td, method, path, token=None if path == "/_lab/reset" else TOKEN)
    assert send(td, method, path, approval=True, token=None if path == "/_lab/reset" else TOKEN)["dry_run"] is True


def test_per_run_request_budget(td):
    for _ in range(60):
        send(td, "GET", "/users/me", run_id="budget")
    with pytest.raises(gateway.GatewayDenied, match="budget exceeded"):
        send(td, "GET", "/users/me", run_id="budget")
    assert send(td, "GET", "/users/me", run_id="another-run")["dry_run"] is True      # budget is per run


def test_per_operation_rate_limit(td):
    for _ in range(10):
        send(td, "DELETE", "/users/4", approval=True, run_id="a", sequence_id="s")
    with pytest.raises(gateway.GatewayDenied, match="rate limit"):
        send(td, "DELETE", "/users/4", approval=True, run_id="b")


def test_kill_switch(td, monkeypatch):
    monkeypatch.setenv("RUNTRACE_KILL_SWITCH", "true")
    g = gateway.SafetyGateway(GW_DIR / "tenantdesk_allowlist.json", base_url="http://localhost:8001", dry_run=True)
    with pytest.raises(gateway.GatewayDenied, match="Kill switch"):
        send(g, "GET", "/tickets/1001")
    g.close()


@pytest.mark.parametrize("url", ["http://example.com:8001", "http://localhost:9999", "https://localhost:8001"])
def test_only_the_allowlisted_local_target_is_accepted(url):
    with pytest.raises(gateway.GatewayDenied):
        gateway.SafetyGateway(GW_DIR / "tenantdesk_allowlist.json", base_url=url, dry_run=True)


def test_redaction_removes_secrets():
    out = gateway.SafetyGateway.redact({"token": "t", "password": "p", "email": "a@b", "nested": [{"Authorization": "Bearer x"}], "status": "open"})
    assert out["token"] == out["password"] == out["email"] == "[REDACTED]"
    assert out["nested"][0]["Authorization"] == "[REDACTED]" and out["status"] == "open"


def test_shopflow_profile_is_independent():
    g = gateway.SafetyGateway(GW_DIR / "shopflow_allowlist.json", base_url="http://localhost:8002", dry_run=True)
    assert g.send(actor="actor-cathy", method="POST", path="/orders/7001/pay", token=TOKEN)["allowlist_id"] == "pay_order"
    with pytest.raises(gateway.GatewayDenied):
        g.send(actor="actor-cathy", method="GET", path="/tickets/1001", token=TOKEN)    # a TenantDesk route is not allowlisted here
    g.close()
