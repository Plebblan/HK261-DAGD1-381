#!/usr/bin/env python3
"""Consistency checks for the *_custom Cyber Range artifacts (stdlib only).

Run from the repo root:  python cyber-range/validate_custom.py
Exit code 0 = all checks pass.
"""
import csv, json, re, sys, collections
from pathlib import Path

R = Path(__file__).resolve().parent
ROOT = R.parent
errors = []
def err(msg): errors.append(msg)

rso = json.loads((R / "model/rso_custom.yaml").read_text(encoding="utf-8"))
wfs = json.loads((R / "workflows/workflows_custom.yaml").read_text(encoding="utf-8"))
objs = json.loads((R / "seed/objects_custom.json").read_text(encoding="utf-8"))
gt = json.loads((R / "schema/ground_truth.json").read_text(encoding="utf-8"))
schema = json.loads((R / "schema/ground_truth.schema.json").read_text(encoding="utf-8"))
with (R / "ground_truth/planted_cases_custom.csv").open(newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

actors = {a["ID"]: a for a in rso["actors"]}
tenants = {t["ID"] for t in rso["tenants"]}
actions = {a["id"]: a for a in rso["actions"]}
objects = {o["ID"] for o in objs["objects"]}
runtime = {o["ID"] for o in objs.get("runtime_objects", [])}
for name, items, key in (("tenants", rso["tenants"], "ID"), ("actors", rso["actors"], "ID"),
                         ("actions", rso["actions"], "id"), ("objects", objs["objects"], "ID"),
                         ("workflows", wfs["workflows"], "ID")):
    dup = [k for k, n in collections.Counter(x[key] for x in items).items() if n > 1]
    if dup: err(f"duplicate {name} ids: {dup}")
for a in rso["actors"]:
    if a["TenantID"] not in tenants: err(f"actor {a['ID']} has unknown tenant {a['TenantID']}")
for o in objs["objects"]:
    if o["TenantID"] not in tenants: err(f"object {o['ID']} has unknown tenant {o['TenantID']}")
    if o["OwnerID"] not in actors: err(f"object {o['ID']} has unknown owner {o['OwnerID']}")

# --- code routes vs model (parsed from source, so FastAPI is not needed) ---
PREFIX = {"tenantdesk": {}, "shopflow": {"login": "shopflow_login", "logout": "shopflow_logout", "get_me": "shopflow_get_me"}}
for app in ("tenantdesk", "shopflow"):
    src = (ROOT / f"app/custom/{app}.py").read_text(encoding="utf-8")
    code = {PREFIX[app].get(m.group(3), m.group(3)): (m.group(1).upper(), m.group(2))
            for m in re.finditer(r'@app\.(get|post|put|patch|delete)\("([^"]+)".*?operation_id="([^"]+)"', src)}
    model = {i: (a["method"], a["path"]) for i, a in actions.items() if a.get("App") == app}
    for i in sorted(set(code) - set(model)): err(f"{app}: route {i} missing from rso_custom")
    for i in sorted(set(model) - set(code)): err(f"{app}: rso_custom action {i} has no route")
    for i in set(code) & set(model):
        if code[i] != model[i]: err(f"{app}: {i} model {model[i]} != code {code[i]}")
    spec = json.loads((ROOT / f"docs/{app}/openapi_{app}.json").read_text(encoding="utf-8"))
    sp = {PREFIX[app].get(o["operationId"], o["operationId"]): (m.upper(), p)
          for p, v in spec["paths"].items() for m, o in v.items()}
    if sp != code: err(f"{app}: OpenAPI doc differs from code routes: {sorted(set(sp.items()) ^ set(code.items()))}")

# --- workflows ---
for w in wfs["workflows"]:
    for s in w["Steps"]:
        if s["Action"].split(":")[0] not in actions: err(f"workflow {w['ID']}: unknown action {s['Action']}")

# --- ground truth CSV ---
req = schema["required"]
pat = re.compile(schema["properties"]["case_id"]["pattern"])
ids = [r["case_id"] for r in rows]
for i in {x for x in ids if ids.count(x) > 1}: err(f"duplicate case_id {i}")
std_ids = set()
with (R / "ground_truth/planted_cases.csv").open(newline="", encoding="utf-8") as f:
    std_ids = {r["case_id"] for r in csv.DictReader(f)}
for i in set(ids) & std_ids: err(f"case_id {i} also exists in planted_cases.csv")
gtd = {g["id"]: g for g in gt}
for r in rows:
    c = r["case_id"]
    if list(r.keys()) != req: err(f"{c}: columns differ from schema order")
    if not pat.fullmatch(c): err(f"{c}: bad case_id")
    try: json.loads(r["evidence_required"])
    except Exception: err(f"{c}: evidence_required is not JSON")
    if r["operation_id"] not in actions and not r["operation_id"] in {k.replace("shopflow_", "") for k in actions}:
        err(f"{c}: operation_id {r['operation_id']} not in rso_custom")
    elif actions.get(r["operation_id"], {}).get("App", r["app"]) != r["app"]:
        err(f"{c}: operation {r['operation_id']} belongs to another app")
    for k in ("attacker", "victim"):
        v = r[k]
        if v and v not in actors and v not in tenants: err(f"{c}: {k} {v} not an actor/tenant")
    if r["attacker"] and actors.get(r["attacker"], {}).get("App") not in (None, r["app"]): err(f"{c}: attacker from another app")
    if r["object_id"] and r["object_id"] not in objects | runtime: err(f"{c}: object {r['object_id']} unknown")
    # method/path must match the model's template
    a = actions.get(r["operation_id"])
    if a:
        rx = "^" + re.sub(r"\{\w+\}", r"[^/]+", a["path"]) + "$"
        if a["method"] != r["method"] or not re.match(rx, r["path"]): err(f"{c}: {r['method']} {r['path']} does not match {a['method']} {a['path']}")
    if r["is_benign"] == "false":
        g = gtd.get(r["flag"])
        if not g: err(f"{c}: flag {r['flag']} missing from ground_truth.json"); continue
        for gk, ck in (("app", "app"), ("family", "family"), ("method", "method"), ("cwe", "cwe"),
                       ("owasp_api_2023", "owasp"), ("expected_safe_response", "expected_safe"),
                       ("observed_when_vulnerable", "observed_vulnerable")):
            if g[gk] != r[ck]: err(f"{c}: {ck} '{r[ck]}' != ground_truth.json '{g[gk]}'")
    elif r["flag"]: err(f"{c}: benign case must not have a flag")
flags = {r["flag"] for r in rows if r["flag"]}
for g in gtd:
    if g not in flags: err(f"flag {g} has no CSV case")
for app, n in (("tenantdesk", 17), ("shopflow", 14)):
    got = sum(1 for r in rows if r["app"] == app and r["is_benign"] == "false")
    if got != n: err(f"{app}: {got} planted cases, expected {n}")
    if sum(1 for r in rows if r["app"] == app and r["is_benign"] == "true") < 3: err(f"{app}: fewer than 3 benign cases")
splits = collections.defaultdict(set)
for r in rows: splits[r["app"]].add(r["split"])
for app, s in splits.items():
    if len(s) > 1: err(f"{app}: mixed splits {s}")

print(f"checked {len(rows)} cases, {len(actions)} actions, {len(actors)} actors, {len(objects)} objects, {len(wfs['workflows'])} workflows")
if errors:
    print(f"\n{len(errors)} problem(s):"); [print(" -", e) for e in errors]; sys.exit(1)
print("OK: custom artifacts are consistent")
