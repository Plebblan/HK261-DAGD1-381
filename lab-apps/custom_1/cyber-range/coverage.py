#!/usr/bin/env python3
"""coverage.py - Phase-1 coverage metrics for the custom_1 range (TenantDesk + ShopFlow), computed from the
Safety Gateway event logs. Definitions follow docs/GroundTruth_Metrics_Coverage.md (section 4 and 9.3) and are
fixed BEFORE any result is looked at (acceptance principle): do not change them after viewing a report; bump
`METRICS_VERSION` and write the reason down instead.

    python custom_1/cyber-range/coverage.py                      # reads logs/*_gateway_events.jsonl
    python custom_1/cyber-range/coverage.py --log a.jsonl --log b.jsonl --evidence-dir /tmp/custom_1-evidence \\
           --out custom_1/cyber-range/reports/coverage_report.json --fail-on-kpi

Input    gateway event JSONL (one forwarded request per line); optional runner evidence (seed, flags, gateway denials)
Model    model/rso_custom.yaml, workflows/workflows_custom.yaml, seed/objects_custom.json,
         business_state_graph_custom.yaml (needs PyYAML), ground_truth/ground_truth.yaml, gateway/*_allowlist.json

Metrics (per app and overall)
  operation_coverage        |RSO actions with >=1 valid request| / |RSO actions|                      (KPI table "workflow coverage" wording, >= 0.70)
  workflow_coverage         |workflows with EVERY step executed validly in ONE sequence| / |workflows| (>= 0.70)
                            a step is valid when: 2xx, actor role/ownership match the workflow step, the object's tracked state
                            (seed state or earlier responses of the same run) satisfies the precondition and the response state
                            equals the postcondition (unchanged for no_state_change steps)
  workflow_step_coverage    steps executed validly in any sequence / all workflow steps
  state_transition_coverage graph transitions executed validly / all graph transitions (system transitions: observed state change)
  invalid_edge_probe_coverage  state-transition (F5) planted cases probed / F5 planted cases ; invariants_probed / invariants
  role_object_pair_coverage MEANINGFUL pairs: (actor, seeded object) with actor != owner, where the object type is addressable
                            by an RSO action (path parameter) that the actor's role may call; covered = valid request by that actor on
                            that object. role_object_pair_coverage_raw uses all actors x all seeded objects. (>= 0.60 on the meaningful set)
  valid_sequence_rate       sequences (runs) whose every forwarded step carries valid_request=true
  provenance_rate           forwarded requests with a response_sha256 / forwarded requests (>= 0.95); request_hash_rate for body requests
  planted_case_coverage     planted cases probed (x-lab-case-id) / planted cases, per family; same for benign; verified counted apart
  safety_gate_violations    forwarded requests outside the allowlist + HTTP 5xx responses (= 0); gateway denials are reported, not counted
"""
import argparse, glob, hashlib, json, sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from rangelib import PARAM_TYPE, Routes, load_json  # noqa: E402

METRICS_VERSION = "1.0"
KPI = {"operation_coverage": 0.70, "workflow_coverage": 0.70, "role_object_pair_coverage": 0.60, "provenance_rate": 0.95}
PROFILE_APP = {"custom_1_tenantdesk": "tenantdesk", "custom_1_shopflow": "shopflow"}
APPS = ("tenantdesk", "shopflow")
CREATES = {"create_ticket", "create_document", "create_user", "create_order", "create_product", "request_refund"}


def ratio(a, b):
    return round(a / b, 4) if b else None


def load_events(paths):
    ev = []
    for p in paths:
        for ln, line in enumerate(Path(p).read_text(encoding="utf-8").splitlines(), 1):
            if line.strip():
                try:
                    ev.append(json.loads(line))
                except json.JSONDecodeError as e:
                    sys.exit(f"[error] {p}:{ln}: invalid JSON: {e}")
    return ev


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", action="append", help="gateway event JSONL (repeatable); default logs/*_gateway_events.jsonl")
    ap.add_argument("--evidence-dir", help="runner evidence dir (adds seed, flags, gateway denials)")
    ap.add_argument("--out", default=str(HERE / "reports/coverage_report.json"))
    ap.add_argument("--fail-on-kpi", action="store_true", help="exit 1 when a KPI is not met or the safety count is not 0")
    a = ap.parse_args()
    logs = a.log or sorted(glob.glob(str(HERE / "logs/*_gateway_events.jsonl")))
    if not logs:
        sys.exit("[error] no gateway event logs found; run the traces through the gateway first (run_trace.py)")

    rso, wfs = load_json(HERE / "model/rso_custom.yaml"), load_json(HERE / "workflows/workflows_custom.yaml")
    seed, gt = load_json(HERE / "seed/objects_custom.json"), load_json(HERE / "ground_truth/ground_truth.yaml")
    routes = Routes(rso)
    actors = {x["ID"]: x for x in rso["actors"]}
    actions = {x["id"]: x for x in rso["actions"]}
    allow = {app: load_json(HERE / f"gateway/{app}_allowlist.json") for app in APPS}
    graph = None
    try:
        import yaml
        graph = yaml.safe_load((HERE / "business_state_graph_custom.yaml").read_text(encoding="utf-8"))
    except ImportError:
        print("warning: PyYAML missing - state_transition_coverage / invariants skipped", file=sys.stderr)

    # ---------------------------------------------------------------- normalise events
    events = []
    for e in load_events(logs):
        app = PROFILE_APP.get(e.get("profile_id"))
        if not app:
            continue
        h = e.get("request_headers") or {}
        act, params = routes.match(app, e["method"], e["path"])
        op = e.get("operation_id") or (act["id"] if act else None)
        obj = h.get("x-lab-object-id") or Routes.object_id(params)
        body = e.get("response")
        if act and act["id"] in CREATES and isinstance(body, dict) and "id" in body and 200 <= e["status_code"] < 300:
            obj = f"{act['resource_type']}-{body['id']}"      # the object this request created (overrides the parent id in the path)
        events.append({"app": app, "run": e.get("run_id"), "seq": e.get("sequence_id"), "step": int(e.get("step_idx") or 0), "actor": e.get("actor"),
                       "op": op, "obj": obj, "status": e["status_code"], "valid": str(e.get("valid_request")).lower() == "true",
                       "case": e.get("case_id"), "wf": h.get("x-lab-wf-workflow"), "wf_action": h.get("x-lab-wf-action"),
                       "guard": h.get("x-lab-guard-object"), "method": e["method"], "path": e["path"], "body": body,
                       "resp_hash": e.get("response_sha256"), "req_hash": e.get("request_body_sha256"), "has_req_body": e.get("request") is not None,
                       "control": str(e.get("run_id", "")).endswith("-control"), "trace": e.get("workflow_id")})
    events.sort(key=lambda x: (x["run"] or "", x["step"]))
    seeds = {o["ID"]: o for o in seed["objects"]}

    # ---------------------------------------------------------------- state simulation (per run)
    wf_steps = {w["ID"]: {s["Action"]: s for s in w["Steps"]} for w in wfs["workflows"]}
    wf_app = {w["ID"]: w["App"] for w in wfs["workflows"]}
    valid_steps = defaultdict(set)          # run -> {(workflow, action)}
    run_app = {}
    transitions_done, system_done = set(), set()
    state, owner = {}, {}
    cur_run = None
    graph_trans = {}
    if graph:
        for app, spec in graph["apps"].items():
            for ename, ent in spec["entities"].items():
                for t in ent["transitions"]:
                    graph_trans[t["id"]] = {**t, "app": app, "entity": ename}
    wf_to_tr = {t["workflow_action"]: tid for tid, t in graph_trans.items() if t.get("workflow_action")}
    for e in events:
        if e["control"] or not e["run"]:
            continue
        if e["run"] != cur_run:
            cur_run = e["run"]
            state = {oid: o["State"] for oid, o in seeds.items() if o["App"] == e["app"] and o.get("State")}
            owner = {oid: o["OwnerID"] for oid, o in seeds.items() if o["App"] == e["app"]}
        run_app[e["run"]] = e["app"]
        ok2 = 200 <= e["status"] < 300
        new_state = e["body"].get("status") if isinstance(e["body"], dict) and ok2 and e["obj"] else None
        if e["wf"] and e["wf_action"] and ok2 and e["valid"]:
            step = wf_steps.get(e["wf"], {}).get(e["wf_action"])
            if step:
                pre, post = step.get("Precondition", {}), step.get("Postcondition")
                good = True
                if "Role" in pre and actors.get(e["actor"], {}).get("Role") not in pre["Role"]:
                    good = False
                guard_obj = e["guard"] or e["obj"]
                before = state.get(guard_obj)
                is_create = e["wf_action"].startswith("create_") or (e["wf_action"] == "request_refund")
                if "State" in pre and before not in pre["State"]:
                    good = False
                if pre.get("Owner") and owner.get(e["obj"]) != e["actor"]:
                    good = False
                if pre.get("NotOwner") and owner.get(e["obj"]) == e["actor"]:
                    good = False
                if isinstance(post, dict) and "State" in post:
                    if new_state != post["State"]:
                        good = False
                elif post == "no_state_change" and before is not None and new_state is not None and new_state != before:
                    good = False
                if good:
                    valid_steps[e["run"]].add((e["wf"], e["wf_action"]))
                    tr = wf_to_tr.get(e["wf_action"])
                    if tr:
                        transitions_done.add(tr)
                if is_create and e["obj"] and good:
                    owner[e["obj"]] = e["actor"]
        # observed system transitions (state change seen in any response about an object)
        if new_state and e["obj"]:
            prev = state.get(e["obj"])
            if prev and prev != new_state:
                for tid, t in graph_trans.items():
                    if t.get("system") and t["app"] == e["app"] and prev in t["from"] and new_state == t["to"] and e["obj"].startswith(t["entity"]):
                        system_done.add(tid)
            state[e["obj"]] = new_state
    transitions_done |= system_done

    # ---------------------------------------------------------------- metrics
    def per_app(app):
        ev = [e for e in events if e["app"] == app]
        run_ev = [e for e in ev if not e["control"]]
        ops = {i for i, x in actions.items() if x["App"] == app}
        op_cov = {e["op"] for e in run_ev if e["valid"] and e["op"] in ops}
        wfl = [w for w in wfs["workflows"] if w["App"] == app]
        runs_app = {r for r, ap_ in run_app.items() if ap_ == app}
        wf_cov, wf_missing, steps_done = [], {}, set()
        total_steps = {(w["ID"], s["Action"]) for w in wfl for s in w["Steps"]}
        for r in runs_app:
            steps_done |= valid_steps[r]
        for w in wfl:
            need = {(w["ID"], s["Action"]) for s in w["Steps"]}
            best = min((need - valid_steps[r] for r in runs_app), key=len, default=need)
            if not best:
                wf_cov.append(w["ID"])
            else:
                wf_missing[w["ID"]] = sorted(x[1] for x in best)
        tr_all = [t for t, x in graph_trans.items() if x["app"] == app]
        tr_cov = [t for t in tr_all if t in transitions_done]
        # pairs
        objs = [o for o in seed["objects"] if o["App"] == app]
        acts_app = [x for x in rso["actions"] if x["App"] == app]
        addr = defaultdict(list)
        for x in acts_app:
            for p, t in PARAM_TYPE.items():
                if "{" + p + "}" in x["path"]:
                    addr[t].append(x)
        app_actors = [x for x in rso["actors"] if x["App"] == app]
        raw = {(ac["ID"], o["ID"]) for ac in app_actors for o in objs if o["OwnerID"] != ac["ID"]}
        meaningful = {(ac["ID"], o["ID"]) for ac in app_actors for o in objs if o["OwnerID"] != ac["ID"]
                      and any("*" in x["roles"] or ac["Role"] in x["roles"] for x in addr.get(o["ResourceType"], []))}
        touched = {(e["actor"], e["obj"]) for e in run_ev if e["valid"] and e["obj"]}
        cross = {p for p in meaningful if actors[p[0]]["TenantID"] != seeds[p[1]]["TenantID"]}
        # sequences / provenance
        seqs = defaultdict(list)
        for e in run_ev:
            seqs[e["run"]].append(e)
        # planted cases
        cases = [c for c in gt["cases"] if c["app"] == app]
        planted = [c for c in cases if not c["is_benign"]]
        benign = [c for c in cases if c["is_benign"]]
        seen = {e["case"] for e in ev if e["case"]}
        fam = defaultdict(lambda: [0, 0])
        for c in planted:
            fam[c["family"]][0] += 1
            fam[c["family"]][1] += c["case_id"] in seen
        f5 = [c for c in planted if c["family"] == "F5" or "F5" in c["secondary_families"]]
        inv_all = {i["id"] for ent in graph["apps"][app]["entities"].values() for i in ent["invariants"]} if graph else set()
        inv_probed = {c["invariant_id"] for c in planted if c.get("invariant_id", "").split("-")[0] in {i.split("-")[0] for i in inv_all} and c["case_id"] in seen and c.get("invariant_id") in inv_all}
        # safety
        entries = [(x["method"], x["path"]) for x in allow[app]["entries"] if x.get("allow")]
        def allowed(e):
            import re
            return any(m == e["method"] and re.fullmatch(re.sub(r"\{[^/{}]+\}", "[^/]+", p).rstrip("/") + "/?", e["path"]) for m, p in entries)
        outside = [e for e in ev if not allowed(e)]
        errors5 = [e for e in ev if e["status"] >= 500]
        return {
            "forwarded_requests": len(ev), "sequences": len(seqs),
            "operation_coverage": ratio(len(op_cov), len(ops)), "operations_uncovered": sorted(ops - op_cov),
            "workflow_coverage": ratio(len(wf_cov), len(wfl)), "workflows_uncovered": wf_missing,
            "workflow_step_coverage": ratio(len(steps_done & total_steps), len(total_steps)),
            "state_transition_coverage": ratio(len(tr_cov), len(tr_all)) if graph else None,
            "transitions_uncovered": sorted(set(tr_all) - set(tr_cov)) if graph else None,
            "invalid_edge_probe_coverage": ratio(sum(c["case_id"] in seen for c in f5), len(f5)),
            "invariants_probed": ratio(len(inv_probed), len(inv_all)) if graph else None,
            "role_object_pair_coverage": ratio(len(meaningful & touched), len(meaningful)),
            "pairs_meaningful": [len(meaningful & touched), len(meaningful)],
            "role_object_pair_coverage_raw": ratio(len(raw & touched), len(raw)),
            "pairs_raw": [len(raw & touched), len(raw)],
            "cross_tenant_pair_coverage": ratio(len(cross & touched), len(cross)),
            "pairs_uncovered_meaningful": sorted(f"{x} -> {y}" for x, y in meaningful - touched),
            "valid_sequence_rate": ratio(sum(all(x["valid"] for x in s) for s in seqs.values()), len(seqs)),
            "provenance_rate": ratio(sum(bool(e["resp_hash"]) for e in ev), len(ev)),
            "request_hash_rate": ratio(sum(bool(e["req_hash"]) for e in ev if e["has_req_body"]), sum(1 for e in ev if e["has_req_body"])),
            "planted_cases": {"total": len(planted), "probed": sum(c["case_id"] in seen for c in planted),
                              "by_family": {k: {"total": v[0], "probed": v[1]} for k, v in sorted(fam.items())},
                              "unprobed": sorted(c["case_id"] for c in planted if c["case_id"] not in seen),
                              "verified": sum(1 for c in planted if c.get("verified_by"))},
            "benign_cases": {"total": len(benign), "probed": sum(c["case_id"] in seen for c in benign)},
            "safety_gate_violations": len(outside) + len(errors5),
            "safety_detail": {"outside_allowlist": len(outside), "http_5xx": len(errors5)},
        }

    report = {"metrics_version": METRICS_VERSION, "inputs": {Path(p).name: hashlib.sha256(Path(p).read_bytes()).hexdigest()[:16] for p in logs},
              "n_events": len(events), "per_app": {app: per_app(app) for app in APPS}}
    pa = report["per_app"]
    def pool(key, num, den):
        n = sum(pa[x][key][num] for x in APPS); d = sum(pa[x][key][den] for x in APPS)
        return ratio(n, d)
    wf_total = {x: len([w for w in wfs["workflows"] if w["App"] == x]) for x in APPS}
    ops_total = {x: len([a_ for a_ in actions.values() if a_["App"] == x]) for x in APPS}
    overall = {
        "operation_coverage": ratio(sum(round((pa[x]["operation_coverage"] or 0) * ops_total[x]) for x in APPS), sum(ops_total.values())),
        "workflow_coverage": ratio(sum(round((pa[x]["workflow_coverage"] or 0) * wf_total[x]) for x in APPS), sum(wf_total.values())),
        "role_object_pair_coverage": pool("pairs_meaningful", 0, 1), "role_object_pair_coverage_raw": pool("pairs_raw", 0, 1),
        "provenance_rate": ratio(sum(round((pa[x]["provenance_rate"] or 0) * pa[x]["forwarded_requests"]) for x in APPS), sum(pa[x]["forwarded_requests"] for x in APPS)),
        "planted_cases_total": sum(pa[x]["planted_cases"]["total"] for x in APPS),
        "planted_cases_probed": sum(pa[x]["planted_cases"]["probed"] for x in APPS),
        "planted_cases_verified": sum(pa[x]["planted_cases"]["verified"] for x in APPS),
        "safety_gate_violations": sum(pa[x]["safety_gate_violations"] for x in APPS)}
    report["overall"] = overall
    kpi = {k: ("PASS" if (overall[k] or 0) >= t else "FAIL") for k, t in KPI.items()}
    kpi["planted_cases_total>=20"] = "PASS" if overall["planted_cases_total"] >= 20 else "FAIL"
    kpi["safety_gate_violations=0"] = "PASS" if overall["safety_gate_violations"] == 0 else "FAIL"
    report["kpi_check"] = kpi
    report["kpi_notes"] = ["Planted cases are 'pending-human-review': probed is not the same as verified.",
                           "Anonymous steps are blocked by the gateway allowlist (auth_required) and do not appear in the event log.",
                           "provenance_rate hashes the response body (gateway response_sha256); the request hash is only logged for requests with a body."]
    if a.evidence_dir:
        runs = []
        for f in sorted(Path(a.evidence_dir).glob("*.evidence.json")):
            ev_ = load_json(f)
            runs.append({"trace": ev_["trace_id"], "app": ev_["app"], "run_id": ev_["run_id"], "seed": ev_.get("seed"), "enabled_flaws": ev_.get("enabled_flaws"),
                         "via_gateway": ev_.get("via_gateway"), "step_failures": ev_["failures"], "gateway_denials": ev_.get("gateway_denials")})
        report["runs"] = runs
        report["gateway_denials_total"] = sum(r["gateway_denials"] or 0 for r in runs)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"overall": overall, "kpi_check": kpi}, indent=2))
    print(f"report: {a.out}")
    if a.fail_on_kpi and "FAIL" in kpi.values():
        sys.exit(1)


if __name__ == "__main__":
    main()
