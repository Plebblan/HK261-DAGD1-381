"""Replay every planted + benign case of the custom apps against the vulnerable build
(only that flaw on) and the patched twin (ENABLED_FLAWS=NONE)."""
import importlib
import pytest
from fastapi.testclient import TestClient

KEY = {"X-Lab-Key": "lab-only-synthetic-key"}


def client(mod, flaws):
    m = importlib.import_module(f"app.custom.{mod}")
    return TestClient(m.create_app(set(flaws)))


def call(c, who, method, path, json=None):
    r = c.post("/auth/login", json={"username": who, "password": f"pw-{who}"})
    assert r.status_code == 200, r.text
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    return c.request(method, path, json=json, headers=h)


# (flag, app, who, method, path, body, setup, vulnerable?(resp), patched status)
def _doc_setup(c):
    r = call(c, "adam", "POST", "/documents", {"title": "x"})
    call(c, "adam", "POST", f"/documents/{r.json()['id']}/submit")
    return r.json()["id"]

TD = [
    ("TD-01", "amy", "GET", "/tickets/1002", None, lambda r: r.status_code == 200, 403),
    ("TD-02", "amy", "GET", "/documents/2004", None, lambda r: r.status_code == 200, 404),
    ("TD-03", "amy", "PATCH", "/tickets/1002", {"title": "pwn"}, lambda r: r.status_code == 200, 403),
    ("TD-04", "amy", "PATCH", "/users/me", {"role": "admin"}, lambda r: r.status_code == 200 and r.json()["role"] == "admin", 403),
    ("TD-05", "amy", "PATCH", "/tickets/1001", {"status": "closed"}, lambda r: r.status_code == 200, 403),
    ("TD-06", "amy", "GET", "/users/4", None, lambda r: "api_key" in r.json(), 200),
    ("TD-07", "ann", "GET", "/tickets/1002/comments", None, lambda r: any(x["internal"] for x in r.json()), 200),
    ("TD-08", "adam", "POST", "/users", {"username": "evil", "role": "admin"}, lambda r: r.status_code == 201, 403),
    ("TD-09", "adam", "GET", "/admin/audit", None, lambda r: r.status_code == 200, 403),
    ("TD-10", "adam", "DELETE", "/users/4", None, lambda r: r.status_code == 200, 403),
    ("TD-11", "adam", "POST", "/tickets/1001/assign", {"assignee_id": 6}, lambda r: r.status_code == 200, 400),
    ("TD-12", "adam", "POST", "/tickets/1001/transition", {"to": "closed"}, lambda r: r.status_code == 200, 409),
    ("TD-14", "ann", "PUT", "/documents/2002", {"content": "changed"}, lambda r: r.status_code == 200, 409),
    ("TD-15", "adam", "GET", "/users", None, lambda r: any(u["tenant"] == "globex" for u in r.json()), 200),
    ("TD-16", "ann", "DELETE", "/documents/2001", None, lambda r: r.status_code == 200, 403),
    ("TD-17", "amy", "POST", "/documents/2001/share", {"user_id": 7}, lambda r: r.status_code == 200, 400),
]
SF = [
    ("SF-01", "carl", "GET", "/orders/7001", None, lambda r: r.status_code == 200, 403),
    ("SF-02", "steve", "GET", "/orders/7001", None, lambda r: r.status_code == 200, 404),
    ("SF-03", "carl", "PATCH", "/orders/7001", {"address": "evil"}, lambda r: r.status_code == 200, 403),
    ("SF-04", "cathy", "PATCH", "/orders/7001", {"total": 1}, lambda r: r.status_code == 200, 403),
    ("SF-05", "cathy", "POST", "/orders", {"items": [{"product_id": 501, "qty": 1, "unit_price": 1}]}, lambda r: r.json()["total"] == 1, 201),
    ("SF-06", "cathy", "POST", "/orders/7003/ship", None, lambda r: r.status_code == 200, 403),
    ("SF-08", "cathy", "GET", "/reports/sales", None, lambda r: r.status_code == 200, 403),
    ("SF-09", "sam", "POST", "/orders/7001/ship", None, lambda r: r.status_code == 200, 409),
    ("SF-12", "cathy", "POST", "/orders/7005/cancel", None, lambda r: r.status_code == 200, 409),
    ("SF-13", "cathy", "POST", "/orders/7001/apply-coupon", {"code": "GLOBEX15"}, lambda r: r.status_code == 200, 404),
    ("SF-14", "cathy", "GET", "/products", None, lambda r: all("cost_price" in p for p in r.json()), 200),
]


@pytest.mark.parametrize("app,rows", [("tenantdesk", TD), ("shopflow", SF)])
def test_simple_cases(app, rows):
    for flag, who, method, path, body, vuln, safe in rows:
        r = call(client(app, {flag}), who, method, path, body)
        assert vuln(r), f"{flag} did not fire when enabled: {r.status_code} {r.text}"
        r = call(client(app, set()), who, method, path, body)
        assert r.status_code == safe and not (safe in (200, 201) and vuln(r)), f"{flag} leaks when patched: {r.status_code}"


def test_td13_self_approval():
    for flaws, expect in (({"TD-13"}, 200), (set(), 403)):
        c = client("tenantdesk", flaws)
        did = _doc_setup(c)
        assert call(c, "adam", "POST", f"/documents/{did}/approve").status_code == expect


def test_sf07_staff_approves_refund():
    for flaws, expect in (({"SF-07"}, 200), (set(), 403)):
        c = client("shopflow", flaws)
        call(c, "cathy", "POST", "/orders/7003/refund", {"amount": 100})
        assert call(c, "sam", "POST", "/refunds/9001/approve").status_code == expect


def test_sf10_double_refund():
    for flaws, expect in (({"SF-10"}, 201), (set(), 409)):
        c = client("shopflow", flaws)
        assert call(c, "cathy", "POST", "/orders/7003/refund", {"amount": 3000}).status_code == 201
        assert call(c, "cathy", "POST", "/orders/7003/refund", {"amount": 3000}).status_code == expect


def test_sf11_exhausted_coupon():
    for flaws, expect in (({"SF-11"}, 200), (set(), 409)):
        c = client("shopflow", flaws)
        assert call(c, "cathy", "POST", "/orders/7001/apply-coupon", {"code": "ACME10"}).status_code == 200
        assert call(c, "carl", "POST", "/orders/7002/apply-coupon", {"code": "ACME10"}).status_code == expect


BENIGN = [
    ("tenantdesk", "amy", "GET", "/tickets/1001", None), ("tenantdesk", "alice", "GET", "/admin/audit", None),
    ("tenantdesk", "amy", "PATCH", "/tickets/1001", {"title": "t"}), ("tenantdesk", "amy", "GET", "/tickets", None),
    ("tenantdesk", "adam", "POST", "/tickets/1002/transition", {"to": "resolved"}),
    ("shopflow", "cathy", "GET", "/orders/7001", None), ("shopflow", "sam", "POST", "/orders/7003/ship", None),
    ("shopflow", "cathy", "PATCH", "/orders/7001", {"address": "a"}), ("shopflow", "cathy", "GET", "/orders", None),
    ("shopflow", "cathy", "POST", "/orders/7001/pay", None),
]


@pytest.mark.parametrize("app,who,method,path,body", BENIGN)
@pytest.mark.parametrize("mode", ["patched", "all-flaws-on"])
def test_benign_is_allowed(app, who, method, path, body, mode):
    c = client(app, set() if mode == "patched" else getattr(importlib.import_module(f"app.custom.{app}"), "FLAWS"))
    assert call(c, who, method, path, body).status_code == 200
