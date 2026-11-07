#!/usr/bin/env python3
"""Replay ground_truth.yaml in-process: every planted case on the vulnerable build (only its flag on)
and on the patched twin (ENABLED_FLAWS=NONE); every benign case on both.

Run from lab-apps/:   python custom_1/cyber-range/replay_ground_truth.py
Needs fastapi + httpx (see custom_1/requirements-dev.txt). Exit code 0 = ground truth matches the apps.
"""
import importlib, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))          # lab-apps/ so that `custom_1` is importable
from fastapi.testclient import TestClient            # noqa: E402

GT = json.loads((HERE / "ground_truth/ground_truth.yaml").read_text(encoding="utf-8"))


def new_client(app, flaws):
    return TestClient(importlib.import_module(f"custom_1.{app}").create_app(set(flaws)))


def call(c, actor, method, path, body=None, headers=None):
    h = dict(headers or {})
    if actor != "anonymous":
        user = actor.replace("actor-", "")
        r = c.request("POST", "/auth/login", json={"username": user, "password": f"pw-{user}"})
        assert r.status_code == 200, r.text
        h["Authorization"] = f"Bearer {r.json()['token']}"
    return c.request(method, path, json=body, headers=h)


def vulnerable(cond, status, payload):
    """Machine-checkable form of observed_when_enabled (see oracle_execution in the ground truth)."""
    rows = payload if isinstance(payload, list) else []
    obj = payload if isinstance(payload, dict) else {}
    if cond.get("status_2xx") and not 200 <= status < 300: return False
    if "body_has_key" in cond and cond["body_has_key"] not in obj: return False
    if "body_field_eq" in cond and any(obj.get(k) != v for k, v in cond["body_field_eq"].items()): return False
    if "list_any" in cond and not any(all(r.get(k) == v for k, v in cond["list_any"].items()) for r in rows): return False
    if "list_all_have_key" in cond and not (rows and all(cond["list_all_have_key"] in r for r in rows)): return False
    return True


def run(case, flaws):
    c = new_client(case["app"], flaws)
    for s in case["setup_steps"]:
        r = call(c, s["actor"], s["method"], s["path"], s.get("body"))
        assert r.status_code == s["expect_status"], f"{case['case_id']}: setup {s['path']} -> {r.status_code} {r.text}"
    return call(c, case["attacker"], case["method"], case["path"], case["request_body"] or None, case["request_headers"])


def main():
    bad, n = [], 0
    for case in GT["cases"]:
        safe = case["expected_safe_status"]
        if case["is_benign"]:
            modes = [("patched", [], False), ("all-flaws-on", None, False)]
        else:
            modes = [("patched", [], False), (f"{case['flag']}-only", [case["flag"]], True)]
        for label, flaws, expect_vuln in modes:
            if flaws is None:
                flaws = importlib.import_module(f"custom_1.{case['app']}").FLAWS
            r = run(case, flaws)
            try: payload = r.json()
            except Exception: payload = None
            n += 1
            if case["is_benign"]:
                ok = r.status_code in safe
                if ok and "list_invariant_all_rows" in case:
                    m = case["list_invariant_all_rows"]
                    ok = bool(payload) and all(all(x.get(k) == v for k, v in m.items()) for x in payload)
            elif expect_vuln:
                ok = vulnerable(case["vulnerable_if"], r.status_code, payload)
            else:
                ok = r.status_code in safe and not vulnerable(case["vulnerable_if"], r.status_code, payload)
            if not ok:
                bad.append(f"{case['case_id']} [{label}] status={r.status_code} body={str(payload)[:120]}")
    print(f"replayed {len(GT['cases'])} cases in {n} runs")
    if bad:
        print(f"{len(bad)} mismatch(es):"); [print(" -", b) for b in bad]; sys.exit(1)
    print("OK: ground truth matches vulnerable and patched builds")


if __name__ == "__main__":
    main()
