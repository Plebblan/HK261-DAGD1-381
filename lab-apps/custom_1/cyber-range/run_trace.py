#!/usr/bin/env python3
"""Replay a valid-sequence trace script against a running custom_1 app (stdlib only).

    python cyber-range/run_trace.py cyber-range/traces/trace_td_01_ticket_lifecycle.json
    python cyber-range/run_trace.py --all --evidence-dir /tmp/custom_1-evidence

* Safe baseline: the target must run with ENABLED_FLAWS=NONE (patched twin). Probes carry
  `case_id` and are expected to be denied; valid-sequence steps are expected to succeed.
* Each trace needs a clean seed: the runner calls POST /_lab/reset first (disable with --no-reset).
* Producer/consumer links: `capture` stores response fields, `{var}` in path/body consumes them.
* Evidence is written per trace (tokens redacted, SHA-256 of the unredacted exchange kept as raw_hash).
"""
import argparse, hashlib, json, os, sys, time, urllib.error, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_URL = {"tenantdesk": "http://127.0.0.1:8001", "shopflow": "http://127.0.0.1:8002"}
LAB_KEY = os.getenv("LAB_KEY", "lab-only-synthetic-key")


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
        with urllib.request.urlopen(r, timeout=10) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    try:
        payload = json.loads(raw) if raw else None
    except ValueError:
        payload = {"_raw": raw.decode(errors="replace")}
    return status, payload


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
    return {k: ("[REDACTED_BEARER_TOKEN]" if k.lower() == "authorization" else v) for k, v in (h or {}).items()}


def run_trace(path, base=None, reset=True, verbose=True):
    t = json.loads(Path(path).read_text(encoding="utf-8"))
    base = base or DEFAULT_URL[t["app"]]
    if reset:
        st, _ = http(base, "POST", "/_lab/reset", headers={"X-Lab-Key": LAB_KEY})
        if st != 200:
            raise SystemExit(f"{t['id']}: reset failed ({st}); is the app up at {base} and LAB_KEY correct?")
    health = http(base, "GET", "/_lab/health")[1] or {}
    if health.get("enabled_flaws"):
        print(f"  WARNING: flaws enabled {health['enabled_flaws']} - valid-sequence baselines expect ENABLED_FLAWS=NONE")
    tokens, vars_, evidence, failures = {}, {}, [], 0
    for i, step in enumerate(t["steps"]):
        actor = step["actor"]
        if step["dsl"] == "login":
            user = actor.replace("actor-", "")
            st, p = http(base, "POST", "/auth/login", {"username": user, "password": f"pw-{user}"})
            ok = st == 200
            if ok:
                tokens[actor] = p["token"]
            rec = {"step": i, "id": step["id"], "actor": actor, "status": st, "ok": ok, "kind": "login"}
        else:
            body = subst(step.get("body"), vars_) if "body" in step else None
            p_ = subst(step["path"], vars_)
            tok = None if actor == "anonymous" else tokens.get(actor)
            if actor != "anonymous" and tok is None:
                raise SystemExit(f"{t['id']}: step {step['id']} uses {actor} before login")
            t0 = time.time()
            st, p = http(base, step["method"], p_, body, step.get("headers"), tok)
            want = step["expect_status"] if isinstance(step["expect_status"], list) else [step["expect_status"]]
            problems = [] if st in want else [f"status {st}, expected {want}"]
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
            rec = {"step": i, "id": step["id"], "actor": actor, "case_id": step.get("case_id"),
                   "request": {"method": step["method"], "url": base + p_, "headers": redact({**(step.get("headers") or {}),
                               **({"Authorization": "x"} if tok else {})}), "body": body},
                   "response": {"status_code": st, "body": None if step["id"].startswith("login") else p},
                   "wf": step.get("wf"), "ok": not problems, "problems": problems,
                   "raw_hash": hashlib.sha256(raw.encode()).hexdigest(), "elapsed_ms": round((time.time() - t0) * 1000, 1)}
        evidence.append(rec)
        if not rec["ok"]:
            failures += 1
        if verbose:
            mark = "PASS" if rec["ok"] else "FAIL"
            extra = f"  <- {'; '.join(rec.get('problems', []))}" if not rec["ok"] else ""
            print(f"  [{mark}] {i:02d} {step['id']}{' ('+step['case_id']+')' if step.get('case_id') else ''}{extra}")
    return {"trace_id": t["id"], "app": t["app"], "base_url": base, "seed": health.get("seed"),
            "sequence_kind": t.get("sequence_kind"), "steps_total": len(t["steps"]), "failures": failures,
            "covers_cases": t.get("covers_cases", []), "steps": evidence}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("traces", nargs="*", help="trace JSON file(s)")
    ap.add_argument("--all", action="store_true", help="run every trace in cyber-range/traces for its default port")
    ap.add_argument("--base-url", help="override target URL (single app only)")
    ap.add_argument("--no-reset", action="store_true")
    ap.add_argument("--evidence-dir", default=None)
    a = ap.parse_args()
    files = sorted((HERE / "traces").glob("*.json")) if a.all else [Path(x) for x in a.traces]
    if not files:
        ap.error("give a trace file or --all")
    total_fail = 0
    for f in files:
        print(f"== {f.name}")
        res = run_trace(f, a.base_url, reset=not a.no_reset)
        total_fail += res["failures"]
        print(f"   {res['steps_total'] - res['failures']}/{res['steps_total']} steps passed")
        if a.evidence_dir:
            Path(a.evidence_dir).mkdir(parents=True, exist_ok=True)
            (Path(a.evidence_dir) / f"{res['trace_id']}.evidence.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    sys.exit(1 if total_fail else 0)


if __name__ == "__main__":
    main()
