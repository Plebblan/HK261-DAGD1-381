#!/usr/bin/env python3
"""Consistency checks for the custom_1 Cyber Range artifacts (TenantDesk + ShopFlow).

Run from anywhere:  python lab-apps/custom_1/cyber-range/validate_custom.py
Needs PyYAML only to read docs/Taxonomy/families.yaml (taxonomy checks are skipped with a warning without it).
Exit code 0 = all checks pass.

Checks
  model      : RSO / workflows / seed internal references, code routes == RSO == OpenAPI
  taxonomy   : ground_truth.yaml follows docs/Taxonomy/families.yaml (D1 one primary family, oracle per family,
               per-family evidence fields, safe statuses), planted cases <-> flags in the app source
  traces     : every trace is a VALID SEQUENCE of workflows_custom.yaml (role, pre-state, post-state per step),
               every request is a modelled route, every ground-truth case is probed by its trace_ref,
               every workflow action is exercised by at least one trace
"""
import csv, collections, json, re, sys
from pathlib import Path

R = Path(__file__).resolve().parent
ROOT = R.parent                       # lab-apps/custom_1
REPO = ROOT.parent.parent             # repository root
errors, warns = [], []
err = errors.append

load = lambda p: json.loads(p.read_text(encoding="utf-8"))
rso, wfs = load(R / "model/rso_custom.yaml"), load(R / "workflows/workflows_custom.yaml")
objs, gt = load(R / "seed/objects_custom.json"), load(R / "ground_truth/ground_truth.yaml")
actors = {a["ID"]: a for a in rso["actors"]}
tenants = {t["ID"] for t in rso["tenants"]}
actions = {a["id"]: a for a in rso["actions"]}
objects = {o["ID"] for o in objs["objects"]} | {o["ID"] for o in objs.get("runtime_objects", [])}
PREFIX = {"tenantdesk": {}, "shopflow": {"login": "shopflow_login", "logout": "shopflow_logout", "get_me": "shopflow_get_me"}}

# ------------------------------------------------------------------ model
for name, items, key in (("tenants", rso["tenants"], "ID"), ("actors", rso["actors"], "ID"), ("actions", rso["actions"], "id"),
                         ("objects", objs["objects"], "ID"), ("workflows", wfs["workflows"], "ID")):
    for k, c in collections.Counter(x[key] for x in items).items():
        if c > 1: err(f"duplicate {name} id: {k}")
for a in rso["actors"]:
    if a["TenantID"] not in tenants: err(f"actor {a['ID']} has unknown tenant {a['TenantID']}")
for o in objs["objects"]:
    if o["TenantID"] not in tenants: err(f"object {o['ID']} has unknown tenant {o['TenantID']}")
    if o["OwnerID"] not in actors: err(f"object {o['ID']} has unknown owner {o['OwnerID']}")

src_flags = {}
for app in ("tenantdesk", "shopflow"):
    src = (ROOT / f"{app}.py").read_text(encoding="utf-8")
    code = {PREFIX[app].get(m.group(3), m.group(3)): (m.group(1).upper(), m.group(2))
            for m in re.finditer(r'@app\.(get|post|put|patch|delete)\("([^"]+)".*?operation_id="([^"]+)"', src)
            if not m.group(2).startswith("/_lab")}
    model = {i: (a["method"], a["path"]) for i, a in actions.items() if a.get("App") == app}
    for i in sorted(set(code) - set(model)): err(f"{app}: route {i} missing from rso_custom")
    for i in sorted(set(model) - set(code)): err(f"{app}: rso_custom action {i} has no route")
    for i in set(code) & set(model):
        if code[i] != model[i]: err(f"{app}: {i} model {model[i]} != code {code[i]}")
    spec = load(ROOT / f"docs/{app}/openapi_{app}.json")
    sp = {PREFIX[app].get(o["operationId"], o["operationId"]): (m.upper(), p) for p, v in spec["paths"].items() for m, o in v.items()}
    if sp != code: err(f"{app}: OpenAPI doc differs from code routes: {sorted(set(sp.items()) ^ set(code.items()))}")
    src_flags[app] = set(re.findall(r'"((?:TD|SF)-\d\d)"', src))
for w in wfs["workflows"]:
    for s in w["Steps"]:
        if s["Action"].split(":")[0] not in actions: err(f"workflow {w['ID']}: unknown action {s['Action']}")

# ------------------------------------------------------------------ taxonomy
fam_file = REPO / "docs/Taxonomy/families.yaml"
tax = None
try:
    import yaml
    tax = yaml.safe_load(fam_file.read_text(encoding="utf-8"))
except ImportError:
    warns.append("PyYAML missing: taxonomy cross-checks skipped")
except FileNotFoundError:
    warns.append(f"{fam_file} not found: taxonomy cross-checks skipped")

cases = gt["cases"]
ids = [c["case_id"] for c in cases]
for i, c in collections.Counter(ids).items():
    if c > 1: err(f"duplicate case_id {i}")
tax_fam = {f["id"]: f for f in tax["families"]} if tax else {}
REQ_KEYS = {"case_id", "app", "family", "secondary_families", "scenario", "operation_id", "method", "path", "oracle_type", "expected_safe",
            "expected_safe_status", "flag", "is_benign", "severity", "split", "attacker", "victim", "object_id", "evidence_required",
            "setup_steps", "request_headers", "request_body", "trace_ref", "verification_status"}
for c in cases:
    cid = c["case_id"]
    miss = REQ_KEYS - set(c)
    if miss: err(f"{cid}: missing keys {sorted(miss)}")
    fam = c["family"]
    if tax and fam not in tax_fam: err(f"{cid}: family {fam} not in taxonomy"); continue
    for s in c.get("secondary_families", []):
        if tax and s not in tax_fam: err(f"{cid}: secondary family {s} not in taxonomy")
        if s == fam: err(f"{cid}: secondary family repeats primary (D1)")
    # operation / route / actors / objects
    op = actions.get(c["operation_id"]) or actions.get(PREFIX[c["app"]].get(c["operation_id"], ""))
    if not op or op.get("App") != c["app"]: err(f"{cid}: operation {c['operation_id']} not in rso for {c['app']}")
    else:
        rx = "^" + re.sub(r"\{\w+\}", r"[^/]+", op["path"]) + "$"
        if op["method"] != c["method"] or not re.match(rx, c["path"].split("?")[0]): err(f"{cid}: {c['method']} {c['path']} != {op['method']} {op['path']}")
    for k in ("attacker", "victim"):
        v = c[k]
        if v and v != "anonymous" and v not in actors and v not in tenants: err(f"{cid}: {k} {v} not an actor/tenant")
        if v in actors and actors[v]["App"] != c["app"]: err(f"{cid}: {k} {v} belongs to another app")
    if c["object_id"] and c["object_id"] not in objects: err(f"{cid}: object {c['object_id']} unknown")
    for s in c["setup_steps"]:
        if s["actor"] not in actors: err(f"{cid}: setup actor {s['actor']} unknown")
    if not isinstance(c["expected_safe_status"], list) or not c["expected_safe_status"]: err(f"{cid}: expected_safe_status must be a non-empty list")
    if c["is_benign"]:
        if c["flag"]: err(f"{cid}: benign case must not have a flag")
        if c["oracle_type"] != "benign_behavior": err(f"{cid}: benign oracle_type must be benign_behavior")
        continue
    # --- planted case vs taxonomy
    if tax:
        tf = tax_fam[fam]
        if c["oracle_type"] != tf["oracle"]: err(f"{cid}: oracle_type {c['oracle_type']} != taxonomy {fam} oracle {tf['oracle']}")
        if fam == "F3":
            if c.get("subtype") not in tf["subtypes"]: err(f"{cid}: F3 needs subtype R or W"); continue
            need = tf["subtypes"][c["subtype"]]["evidence_required"]
        else:
            need = list(tf["evidence_required"])
            if "subtype" in c: err(f"{cid}: subtype only applies to F3")
        if fam == "F4" and c.get("collection") is not None: pass
        for e in need:
            if e == "list_contents" and "collection" not in c.get("scenario", "") and "lists" not in c["scenario"]: continue
            if e not in c["evidence_required"]: err(f"{cid}: evidence_required lacks taxonomy field {e}")
        if c["method"] != "GET" and fam == "F3" and c.get("subtype") == "R": err(f"{cid}: F3-R case must be a read")
        # family-specific payload
        if fam == "F1" and c["actor_tenant_id"] != c["object_tenant_id"]: err(f"{cid}: F1 is same-tenant (D1) but tenants differ")
        if fam == "F4" and c["actor_tenant_id"] == c["object_tenant_id"]: err(f"{cid}: F4 must cross a tenant boundary (D1)")
        if fam == "F2" and not c.get("role_matrix_cell"): err(f"{cid}: F2 needs role_matrix_cell")
        if fam == "F5" and not (c.get("attempted_edge") and c.get("violated_invariant")): err(f"{cid}: F5 needs attempted_edge + violated_invariant")
        if fam == "F3" and c["subtype"] == "W" and not c.get("restricted_properties"): err(f"{cid}: F3-W needs restricted_properties")
        if fam == "F3" and c["subtype"] == "R" and not c.get("allowed_field_set"): err(f"{cid}: F3-R needs allowed_field_set")
        if fam == "F5" and any(s in c["expected_safe_status"] for s in (401, 403, 404)) and c["expected_safe_status"] == [200]:
            err(f"{cid}: implausible safe status")
    if c["flag"] not in src_flags.get(c["app"], set()): err(f"{cid}: flag {c['flag']} not found in {c['app']}.py")
    if not c.get("vulnerable_if"): err(f"{cid}: vulnerable_if missing")
    m = c["method"] != "GET" and not c["request_body"] and c["operation_id"] not in {"approve_document", "ship_order", "approve_refund", "cancel_order", "delete_user", "delete_document"}
    if m: err(f"{cid}: write probe without request_body")
planted = [c for c in cases if not c["is_benign"]]
for fam, n in collections.Counter(c["family"] for c in planted).items():
    if gt["family_counts"].get(fam) != n: err(f"family_counts[{fam}] = {gt['family_counts'].get(fam)} but {n} planted cases")
for f in sorted(set().union(*src_flags.values())):
    n = sum(1 for c in planted if c["flag"] == f)
    if n != 1: err(f"flag {f} has {n} planted cases (expected exactly 1)")
for app, n in (("tenantdesk", 17), ("shopflow", 14)):
    if sum(1 for c in planted if c["app"] == app) != n: err(f"{app}: expected {n} planted cases")
    if sum(1 for c in cases if c["app"] == app and c["is_benign"]) < 3: err(f"{app}: fewer than 3 benign cases")
    if len({c["split"] for c in cases if c["app"] == app}) > 1: err(f"{app}: mixed splits")
csv_path = R / "ground_truth/planted_cases_custom.csv"
if csv_path.exists():
    with csv_path.open(newline="", encoding="utf-8") as f: rows = list(csv.DictReader(f))
    if [r["case_id"] for r in rows] != ids: err("planted_cases_custom.csv is out of date: regenerate it from ground_truth.yaml")

# ------------------------------------------------------------------ traces (valid sequences)
wf_steps = {w["ID"]: {s["Action"]: s for s in w["Steps"]} for w in wfs["workflows"]}
role_of = {k: v["Role"] for k, v in actors.items()}
case_ids, covered_actions = set(ids), set()
probed = collections.defaultdict(set)
for tf in sorted((R / "traces").glob("*.json")):
    t = load(tf); tid = t["id"]
    app = t["app"]; states = dict(t.get("objects", {}))
    if tf.stem != tid: err(f"{tf.name}: id {tid} != file name")
    if t.get("flags") != "disabled": err(f"{tid}: valid-sequence traces run with flags disabled")
    logged = set()
    for i, s in enumerate(t["steps"]):
        sid = f"{tid}#{i}:{s['id']}"
        a = s["actor"]
        if s["dsl"] == "login":
            if a not in actors or actors[a]["App"] != app: err(f"{sid}: bad login actor {a}")
            logged.add(a); continue
        if a != "anonymous" and a not in logged: err(f"{sid}: {a} used before login")
        if a != "anonymous" and (a not in actors or actors[a]["App"] != app): err(f"{sid}: actor {a} not in {app}")
        route = next((x for x in actions.values() if x.get("App") == app and x["method"] == s["method"]
                      and re.match("^" + re.sub(r"\{\w+\}", r"[^/]+", x["path"]) + "$", re.sub(r"\{\w+\}", "1", s["path"]))), None)
        if not route: err(f"{sid}: {s['method']} {s['path']} is not a modelled route")
        if s.get("case_id"):
            if s["case_id"] not in case_ids: err(f"{sid}: unknown case_id {s['case_id']}")
            else: probed[s["case_id"]].add(tid)
            if s.get("headers", {}).get("x-lab-case-id") != s["case_id"]: err(f"{sid}: x-lab-case-id header missing")
        w = s.get("wf")
        if not w: continue
        if w["workflow"] not in t["workflows"]: err(f"{sid}: workflow {w['workflow']} not declared in trace"); continue
        step = wf_steps.get(w["workflow"], {}).get(w["action"])
        if not step: err(f"{sid}: action {w['action']} not in {w['workflow']}"); continue
        if w["action"].split(":")[0] != (route or {}).get("id"): err(f"{sid}: request is {(route or {}).get('id')} but wf action is {w['action']}")
        covered_actions.add((w["workflow"], w["action"]))
        pre, post = step.get("Precondition", {}), step.get("Postcondition")
        if "Role" in pre and role_of.get(a) not in pre["Role"]: err(f"{sid}: role {role_of.get(a)} not allowed for {w['action']} (needs {pre['Role']})")
        guard = states.get(w.get("guard_object") or w["object"])
        if "State" in pre:
            if guard is None: err(f"{sid}: no known state for {w.get('guard_object') or w['object']}")
            elif guard not in pre["State"]: err(f"{sid}: INVALID SEQUENCE - {w['action']} needs state {pre['State']}, object is {guard}")
        if isinstance(post, dict) and "State" in post: states[w["object"]] = post["State"]
        elif post == "no_state_change" and w["object"] not in states and guard is not None: states[w["object"]] = guard
        exp = s.get("expect_state")
        if exp and isinstance(post, dict) and "State" in post and exp != post["State"] and w["workflow"] != "workflow-refund":
            err(f"{sid}: expect_state {exp} != workflow postcondition {post['State']}")
    for c in t.get("covers_cases", []):
        if c not in case_ids: err(f"{tid}: covers_cases lists unknown {c}")
        elif tid not in probed[c]: err(f"{tid}: covers {c} but no step carries that case_id")
for c in cases:
    ref = c["trace_ref"]
    if not (R / f"traces/{ref}.json").exists(): err(f"{c['case_id']}: trace_ref {ref} does not exist")
    elif ref not in probed[c["case_id"]]: err(f"{c['case_id']}: not probed in its trace_ref {ref}")
for wid, steps in wf_steps.items():
    for act in steps:
        if (wid, act) not in covered_actions: err(f"workflow action {wid}/{act} is not exercised by any valid-sequence trace")

print(f"checked {len(cases)} cases ({len(planted)} planted), {len(actions)} actions, {len(actors)} actors, "
      f"{len(objects)} objects, {len(wfs['workflows'])} workflows, {len(list((R / 'traces').glob('*.json')))} traces")
for w in warns: print("warning:", w)
if errors:
    print(f"\n{len(errors)} problem(s):"); [print(" -", e) for e in errors]; sys.exit(1)
print("OK: custom_1 artifacts are consistent")
