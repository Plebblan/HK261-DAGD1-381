#!/usr/bin/env python3
"""Replay valid-sequence traces through the shared OpenAPI-driven reverse proxy.

Start one target-scoped proxy process with src.proxy.addon for the same run ID
before executing the runner. TenantDesk listens on 127.0.0.1:8101 and ShopFlow
on 127.0.0.1:8102. Example:

    python lab-apps/custom_1/cyber-range/run_trace.py \
      lab-apps/custom_1/cyber-range/traces/trace_td_01_ticket_lifecycle.json \
      --run-id "$RUN_ID" --run-dir "runs/tenantdesk/$RUN_ID"

RunTrace preserves ordered DSL steps, actor identity, operation/case/workflow
metadata and producer-consumer values. The shared proxy enforces policy and
writes redacted SQLite, JSONL and HAR artifacts. The --direct option is a
debug-only bypass and never produces KPI-eligible gateway evidence.

Each trace resets its disposable target unless --no-reset is supplied. A
reset is a configured extra method and requires the explicit approval header.
"""
import argparse, hashlib, json, os, sys, time, urllib.error, urllib.request, uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rangelib import Routes, load_json  # noqa: E402

HERE = Path(__file__).resolve().parent
GATEWAY_URL = {"tenantdesk": "http://127.0.0.1:8101", "shopflow": "http://127.0.0.1:8102"}
DIRECT_URL = {"tenantdesk": "http://127.0.0.1:8001", "shopflow": "http://127.0.0.1:8002"}
LAB_KEY = os.getenv("LAB_KEY", "lab-only-synthetic-key")
GATEWAY_DENIALS = ("Not allowlisted", "Kill switch", "Per-run request budget", "Per-operation rate limit",
                   "Manual approval required", "Authenticated operation requires actor token", "Gateway accepts loopback",
                   "Upstream unavailable")
ROUTES = Routes(load_json(HERE / "model/rso_custom.yaml"))


def subst(value, vars_):
    if isinstance(value, str):
        for k, v in vars_.items():
            value = value.replace("{" + k + "}", str(v))
        return value
    if isinstance(value, dict):
        return {k: subst(v, vars_) for k, v in value.items()}
    if isinstance(value, list):
        return [subst(v, vars_) for v in value]
    return value


def http(base, method, path, body=None, headers=None, token=None):
    h = {"Content-Type": "application/json", **(headers or {})}
    if token:
        h["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    try:
        payload = json.loads(raw) if raw else None
    except ValueError:
        payload = {"_raw": raw.decode(errors="replace")}
    return status, payload


def gateway_denied(status, payload):
    if not isinstance(payload, dict):
        return False
    if payload.get("gateway_verdict") == "blocked":
        return True
    d = payload.get("detail")
    return status in (403, 502) and isinstance(d, str) and d.startswith(GATEWAY_DENIALS)


def check_expect(exp, payload):
    """Return list of failure strings for the `expect` block of a step."""
    bad = []
    rows = payload if isinstance(payload, list) else []
    obj = payload if isinstance(payload, dict) else {}
    if "no_key" in exp and exp["no_key"] in obj:
        bad.append(f"response exposes forbidden key {exp['no_key']!r}")
    if "no_key_in_rows" in exp and any(exp["no_key_in_rows"] in r for r in rows):
        bad.append(f"rows expose forbidden key {exp['no_key_in_rows']!r}")
    if "no_rows" in exp:
        m = exp["no_rows"]
        if any(all(r.get(k) == v for k, v in m.items()) for r in rows):
            bad.append(f"rows matching {m} must not be returned")
    if "all_rows" in exp:
        m = exp["all_rows"]
        if not rows or not all(all(r.get(k) == v for k, v in m.items()) for r in rows):
            bad.append(f"every row must match {m}")
    if "body_eq" in exp:
        for k, v in exp["body_eq"].items():
            if obj.get(k) != v:
                bad.append(f"body[{k!r}] == {obj.get(k)!r}, expected {v!r}")
    return bad


def redact(h):
    return {k: ("[REDACTED_BEARER_TOKEN]" if k.lower() in ("authorization", "x-lab-key") else v) for k, v in (h or {}).items()}


def redact_payload(value):
    secrets = {"password", "token", "accesstoken", "refreshtoken", "secret", "api_key", "cvv", "otp"}
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if k.lower() in secrets else redact_payload(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_payload(v) for v in value]
    return value


def run_trace(path, base=None, reset=True, verbose=True, direct=False, run_id=None):
    t = load_json(path)
    app = t["app"]
    base = base or (DIRECT_URL if direct else GATEWAY_URL)[app]
    run_id = run_id or os.getenv("RUNTRACE_RUN_ID") or str(uuid.uuid4())
    sequence_id = f"{run_id}-{t['id']}"
    ctl_run = run_id
    def ctl_headers(actor="lab-control", approval=False):
        h = {} if direct else {"x-runtrace-actor": actor, "x-lab-run-id": ctl_run, "x-lab-sequence-id": sequence_id, "x-lab-workflow-id": t["id"], "x-lab-valid-request": "true"}
        if approval and not direct:
            h["x-range-approval"] = "true"
        return h
    if reset:
        st, p = http(base, "POST", "/_lab/reset", headers={"X-Lab-Key": LAB_KEY, **ctl_headers(approval=True)})
        if st != 200:
            raise SystemExit(f"{t['id']}: reset failed ({st} {p}); are the app{'' if direct else ' and gateway'} up at {base}?")
    health = http(base, "GET", "/_lab/health", headers=ctl_headers())[1] or {}
    if health.get("enabled_flaws"):
        print(f"  WARNING: flaws enabled {health['enabled_flaws']} - valid-sequence baselines expect ENABLED_FLAWS=NONE")
    tokens, vars_, evidence, failures, denials = {}, {}, [], 0, 0
    for i, step in enumerate(t["steps"]):
        actor = step["actor"]
        gw = {}
        if not direct:
            gw = {"x-runtrace-actor": actor, "x-lab-run-id": run_id, "x-lab-sequence-id": sequence_id,
                  "x-lab-workflow-id": t["id"], "x-lab-step-index": str(i), "x-lab-case-id": step.get("case_id", ""), "x-lab-valid-request": "true"}
            if step.get("approval"):
                gw["x-range-approval"] = "true"
        if step["dsl"] == "login":
            user = actor.replace("actor-", "")
            action, _ = ROUTES.match(app, "POST", "/auth/login")
            if gw:
                gw["x-lab-operation-id"] = action["id"]
            st, p = http(base, "POST", "/auth/login", {"username": user, "password": f"pw-{user}"}, gw)
            ok = st == 200
            if ok:
                tokens[actor] = p["token"]
            elif gateway_denied(st, p):
                denials += 1
            rec = {"step": i, "id": step["id"], "actor": actor, "status": st, "ok": ok, "kind": "login"}
        else:
            body = subst(step.get("body"), vars_) if "body" in step else None
            p_ = subst(step["path"], vars_)
            tok = None if actor == "anonymous" else tokens.get(actor)
            if actor != "anonymous" and tok is None:
                raise SystemExit(f"{t['id']}: step {step['id']} uses {actor} before login")
            action, params = ROUTES.match(app, step["method"], p_)
            hdr = dict(step.get("headers") or {})
            if gw:
                hdr.update(gw)
                if action:
                    hdr["x-lab-operation-id"] = action["id"]
                obj = ROUTES.object_id(params)
                if obj:
                    hdr["x-lab-object-id"] = obj
                w = step.get("wf")
                if w:
                    hdr["x-lab-wf-workflow"], hdr["x-lab-wf-action"] = w["workflow"], w["action"]
                    if w.get("guard_object"):
                        hdr["x-lab-guard-object"] = subst("{" + w["guard_object"] + "}", vars_) if w["guard_object"] in vars_ else w["guard_object"]
            t0 = time.time()
            st, p = http(base, step["method"], p_, body, hdr, tok)
            want = step["expect_status"] if isinstance(step["expect_status"], list) else [step["expect_status"]]
            blocked = gateway_denied(st, p)
            problems = [] if st in want else [f"status {st}, expected {want}"]
            note = None
            if blocked:
                denials += 1
                if actor == "anonymous" and st in want:
                    note = "blocked by the gateway allowlist (auth_required) before reaching the app"
                else:
                    problems = [f"gateway denied: {p.get('detail')}"]
            if "expect_state" in step and st < 400:
                got = p.get("status") if isinstance(p, dict) else None
                if got != step["expect_state"]:
                    problems.append(f"state {got!r}, expected {step['expect_state']!r}")
            if st < 400 and "expect" in step:
                problems += check_expect(step["expect"], p)
            if st < 400:
                for var, field in step.get("capture", {}).items():
                    vars_[var] = p[field]
            raw = json.dumps({"method": step["method"], "path": p_, "body": body, "status": st, "response": p}, sort_keys=True)
            rec = {"step": i, "id": step["id"], "actor": actor, "case_id": step.get("case_id"), "operation_id": action["id"] if action else None,
                   "request": {"method": step["method"], "url": base + p_, "headers": redact({**hdr, **({"Authorization": "x"} if tok else {})}), "body": redact_payload(body)},
                   "response": {"status_code": st, "body": redact_payload(p)}, "wf": step.get("wf"), "ok": not problems, "problems": problems,
                   "gateway_denied": blocked, **({"note": note} if note else {}),
                   "raw_hash": hashlib.sha256(raw.encode()).hexdigest(), "elapsed_ms": round((time.time() - t0) * 1000, 1)}
        evidence.append(rec)
        if not rec["ok"]:
            failures += 1
        if verbose:
            mark = "PASS" if rec["ok"] else "FAIL"
            extra = f"  <- {'; '.join(rec.get('problems', []))}" if not rec["ok"] else (f"  ({rec['note']})" if rec.get("note") else "")
            print(f"  [{mark}] {i:02d} {step['id']}{' ('+step['case_id']+')' if step.get('case_id') else ''}{extra}")
    return {"trace_id": t["id"], "app": app, "base_url": base, "via_gateway": not direct, "run_id": run_id, "sequence_id": sequence_id,
            "seed": health.get("seed"), "enabled_flaws": health.get("enabled_flaws"), "sequence_kind": t.get("sequence_kind"),
            "steps_total": len(t["steps"]), "failures": failures, "gateway_denials": denials,
            "covers_cases": t.get("covers_cases", []), "steps": evidence}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("traces", nargs="*", help="trace JSON file(s)")
    ap.add_argument("--all", action="store_true", help="run every trace in cyber-range/traces")
    ap.add_argument("--direct", action="store_true", help="bypass the Safety Gateway (debug only, not counted for KPIs)")
    ap.add_argument("--base-url", help="override target URL (single app only)")
    ap.add_argument("--no-reset", action="store_true")
    ap.add_argument("--evidence-dir", default=None)
    ap.add_argument("--run-id", default=os.getenv("RUNTRACE_RUN_ID"))
    ap.add_argument("--run-dir", default=os.getenv("RUNTRACE_RUN_DIR"))
    a = ap.parse_args()
    a.run_id = a.run_id or str(uuid.uuid4())
    files = sorted((HERE / "traces").glob("*.json")) if a.all else [Path(x) for x in a.traces]
    if not files:
        ap.error("give a trace file or --all")
    if a.direct:
        print("WARNING: --direct bypasses the Safety Gateway; this run is not a KPI run.")
    total_fail = 0
    run_results = []
    for f in files:
        print(f"== {f.name}")
        res = run_trace(f, a.base_url, reset=not a.no_reset, direct=a.direct, run_id=a.run_id)
        run_results.append(res)
        total_fail += res["failures"]
        print(f"   {res['steps_total'] - res['failures']}/{res['steps_total']} steps passed, {res['gateway_denials']} gateway denial(s)")
        if a.evidence_dir:
            Path(a.evidence_dir).mkdir(parents=True, exist_ok=True)
            (Path(a.evidence_dir) / f"{res['trace_id']}.evidence.json").write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
        if a.run_dir:
            run_dir = Path(a.run_dir)
            trace_dir = run_dir / "runtrace"
            trace_dir.mkdir(parents=True, exist_ok=True)
            (trace_dir / f"{res['trace_id']}.json").write_text(
                json.dumps(res, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
    if a.run_dir:
        run_dir = Path(a.run_dir)
        summary = {
            "run_id": a.run_id or os.getenv("RUNTRACE_RUN_ID"),
            "trace_count": len(run_results),
            "steps_total": sum(item["steps_total"] for item in run_results),
            "failures": total_fail,
            "gateway_denials": sum(item["gateway_denials"] for item in run_results),
            "traces": [item["trace_id"] for item in run_results],
        }
        (run_dir / "runtrace.json").write_text(
            json.dumps({"summary": summary, "traces": run_results}, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    sys.exit(1 if total_fail else 0)


if __name__ == "__main__":
    main()
