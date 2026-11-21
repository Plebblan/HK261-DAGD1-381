#!/usr/bin/env python3
"""coverage.py - Phase-1 coverage metrics for the custom_1 range (TenantDesk + ShopFlow), computed from the shared proxy Store trace JSONL. Definitions follow docs/GroundTruth_Metrics_Coverage.md (section 4 and 9.3) and are
fixed BEFORE any result is looked at (acceptance principle): do not change them after viewing a report; bump
`METRICS_VERSION` and write the reason down instead.

    python lab-apps/custom_1/cyber-range/coverage.py --log runs/tenantdesk/<run-id>/trace.jsonl --log runs/shopflow/<run-id>/trace.jsonl
    python custom_1/cyber-range/coverage.py --log a.jsonl --log b.jsonl --evidence-dir /tmp/custom_1-evidence \\
           --out custom_1/cyber-range/reports/coverage_report.json --fail-on-kpi

Input    run-scoped Store-exported trace.jsonl (forwarded and denied events); optional RunTrace runtrace.json evidence
Model    model/rso_custom.yaml, workflows/workflows_custom.yaml, seed/objects_custom.json,
         business_state_graph_custom.yaml (needs PyYAML), ground_truth/ground_truth.yaml

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

METRICS_VERSION = "1.1"
KPI = {"operation_coverage": 0.70, "workflow_coverage": 0.70, "role_object_pair_coverage": 0.60, "provenance_rate": 0.95}
PROFILE_APP = {"tenantdesk": "tenantdesk", "shopflow": "shopflow"}
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
    ap.add_argument("--log", action="append", help="run-scoped trace.jsonl (repeatable)")
    ap.add_argument("--evidence-dir", help="runner evidence dir (adds seed, flags, gateway denials)")
    ap.add_argument("--out", default=str(HERE / "reports/coverage_report.json"))
    ap.add_argument("--fail-on-kpi", action="store_true", help="exit 1 when a KPI is not met or the safety count is not 0")
    a = ap.parse_args()
    repo_root = HERE.parents[2]
    logs = a.log or sorted(glob.glob(str(repo_root / "runs/*/*/trace.jsonl")) )
    if not logs:
        sys.exit("[error] no run trace JSONL found; execute RunTrace through the shared proxy first")

    rso, wfs = load_json(HERE / "model/rso_custom.yaml"), load_json(HERE / "workflows/workflows_custom.yaml")
    seed, gt = load_json(HERE / "seed/objects_custom.json"), load_json(HERE / "ground_truth/ground_truth.yaml")
    routes = Routes(rso)
    actors = {x["ID"]: x for x in rso["actors"]}
    actions = {x["id"]: x for x in rso["actions"]}
    graph = None
    try:
        import yaml
        graph = yaml.safe_load((HERE / "business_state_graph_custom.yaml").read_text(encoding="utf-8"))
    except ImportError:
        print("warning: PyYAML missing - state_transition_coverage / invariants skipped", file=sys.stderr)

    # ---------------------------------------------------------------- normalise events
    events = []
    for e in load_events(logs):
        metadata = e.get("metadata") or {}
        app = PROFILE_APP.get(metadata.get("target_id") or e.get("target_id"))
        if not app:
            continue
        request_record = e.get("request_redacted") or {}
        h = request_record.get("headers", {}) if isinstance(request_record, dict) else {}
        request_body = request_record.get("body") if isinstance(request_record, dict) else request_record
        act, params = routes.match(app, e.get("method", "GET"), e.get("path", "/"))
        op = e.get("operation_id") or (act["id"] if act else None)
        obj = metadata.get("object_id") or h.get("x-lab-object-id") or Routes.object_id(params)
        body = e.get("response_redacted")
        status = int(e.get("status") or 0)
        verdict = e.get("gateway_verdict")
        if act and act["id"] in CREATES and isinstance(body, dict) and "id" in body and 200 <= status < 300:
            obj = f"{act['resource_type']}-{body['id']}"
        events.append({
            "app": app, "run": e.get("run_id"), "seq": e.get("sequence_id"),
            "step": int(e.get("step_idx") or 0), "actor": e.get("actor"),
            "op": op, "obj": obj, "status": status,
            "valid": verdict == "forwarded" and bool(e.get("valid_request")),
            "verdict": verdict, "case": e.get("case_id"),
            "wf": metadata.get("wf_workflow"), "wf_action": metadata.get("wf_action"),
            "guard": metadata.get("guard_object"), "method": e.get("method"),
            "path": e.get("path"), "body": body,
            "resp_hash": e.get("response_hash"), "req_hash": e.get("raw_body_hash"),
            "has_req_body": request_body is not None,
            "control": e.get("actor") == "lab-control", "trace": e.get("workflow_id"),
        })
    events.sort(key=lambda x: (x["run"] or "", x["seq"] or "", x["step"]))
    seeds = {o["ID"]: o for o in seed["objects"]}

    # ---------------------------------------------------------------- state simulation (per run)
    wf_steps = {w["ID"]: {s["Action"]: s for s in w["Steps"]} for w in wfs["workflows"]}
    wf_app = {w["ID"]: w["App"] for w in wfs["workflows"]}
    valid_steps = defaultdict(set)          # sequence -> {(workflow, action)}
    sequence_app = {}
    transitions_done, system_done = set(), set()
    state, owner = {}, {}
    cur_sequence = None
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
        if e["seq"] != cur_sequence:
            cur_sequence = e["seq"]
            state = {oid: o["State"] for oid, o in seeds.items() if o["App"] == e["app"] and o.get("State")}
            owner = {oid: o["OwnerID"] for oid, o in seeds.items() if o["App"] == e["app"]}
        sequence_app[e["seq"]] = e["app"]
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
                    valid_steps[e["seq"]].add((e["wf"], e["wf_action"]))
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
        run_ev = [e for e in ev if not e["control"] and e["verdict"] == "forwarded"]
        ops = {i for i, x in actions.items() if x["App"] == app}
        op_cov = {e["op"] for e in run_ev if e["valid"] and e["op"] in ops}
        wfl = [w for w in wfs["workflows"] if w["App"] == app]
        runs_app = {sequence for sequence, ap_ in sequence_app.items() if ap_ == app}
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
            seqs[e["seq"]].append(e)
        # planted cases
        cases = [c for c in gt["cases"] if c["app"] == app]
        planted = [c for c in cases if not c["is_benign"]]
        benign = [c for c in cases if c["is_benign"]]
        seen = {e["case"] for e in run_ev if e["case"]}
        fam = defaultdict(lambda: [0, 0])
        for c in planted:
            fam[c["family"]][0] += 1
            fam[c["family"]][1] += c["case_id"] in seen
        f5 = [c for c in planted if c["family"] == "F5" or "F5" in c["secondary_families"]]
        inv_all = {i["id"] for ent in graph["apps"][app]["entities"].values() for i in ent["invariants"]} if graph else set()
        inv_probed = {c["invariant_id"] for c in planted if c.get("invariant_id", "").split("-")[0] in {i.split("-")[0] for i in inv_all} and c["case_id"] in seen and c.get("invariant_id") in inv_all}
        # safety
        outside = [e for e in run_ev if not e["op"]]
        errors5 = [e for e in run_ev if e["status"] >= 500]
        gateway_denials = [e for e in ev if not e["control"] and e["verdict"] == "blocked"]
        return {
            "forwarded_requests": len(run_ev), "gateway_denials": len(gateway_denials), "sequences": len(seqs),
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
            "safety_detail": {"forwarded_without_rso_operation": len(outside), "http_5xx": len(errors5)},
        }

    report = {"metrics_version": METRICS_VERSION, "inputs": {Path(p).name: hashlib.sha256(Path(p).read_bytes()).hexdigest()[:16] for p in logs},
              "n_events": len(events), "forwarded_events": sum(1 for event in events if event["verdict"] == "forwarded"), "per_app": {app: per_app(app) for app in APPS}}
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
        "safety_gate_violations": sum(pa[x]["safety_gate_violations"] for x in APPS),
        "gateway_denials": sum(pa[x]["gateway_denials"] for x in APPS)}
    report["overall"] = overall
    kpi = {k: ("PASS" if (overall[k] or 0) >= t else "FAIL") for k, t in KPI.items()}
    kpi["planted_cases_total>=20"] = "PASS" if overall["planted_cases_total"] >= 20 else "FAIL"
    kpi["safety_gate_violations=0"] = "PASS" if overall["safety_gate_violations"] == 0 else "FAIL"
    report["kpi_check"] = kpi
    report["kpi_notes"] = ["Metrics v1.1 reads the shared proxy Store trace; sequence IDs, not process run IDs, define one workflow sequence.", "Planted cases are 'pending-human-review': probed is not the same as verified.",
                           "Anonymous and denied steps remain in trace.jsonl with gateway_verdict=blocked; they are excluded from forwarded-operation coverage.",
                           "provenance_rate uses response_hash from the Store response record; raw_body_hash is computed before redaction and only exists when a body was sent."]
    if a.evidence_dir:
        runs = []
        evidence_files = list(Path(a.evidence_dir).glob("*.evidence.json"))
        evidence_files += list(Path(a.evidence_dir).rglob("runtrace.json"))
        for f in sorted(set(evidence_files)):
            ev_ = load_json(f)
            if "traces" in ev_:
                for item in ev_["traces"]:
                    runs.append({"trace": item["trace_id"], "app": item["app"], "run_id": item["run_id"],
                                 "seed": item.get("seed"), "enabled_flaws": item.get("enabled_flaws"),
                                 "via_gateway": item.get("via_gateway"), "step_failures": item["failures"],
                                 "gateway_denials": item.get("gateway_denials")})
            elif "trace_id" in ev_:
                runs.append({"trace": ev_["trace_id"], "app": ev_["app"], "run_id": ev_["run_id"],
                             "seed": ev_.get("seed"), "enabled_flaws": ev_.get("enabled_flaws"),
                             "via_gateway": ev_.get("via_gateway"), "step_failures": ev_["failures"],
                             "gateway_denials": ev_.get("gateway_denials")})
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
