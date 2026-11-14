"""coverage.py on a hand-built gateway event log with hand-computed expected values."""
import json
import subprocess
import sys
from pathlib import Path

RANGE = Path(__file__).resolve().parents[1] / "lab-apps" / "custom_1" / "cyber-range"
RUN = "run-1"


def ev(step, actor, method, path, status, op, body=None, case=None, obj=None, valid="true", wf=None, wf_action=None, resp_hash="h", run=RUN):
    h = {"x-lab-operation-id": op, "x-lab-valid-request": valid}
    if case: h["x-lab-case-id"] = case
    if obj: h["x-lab-object-id"] = obj
    if wf: h["x-lab-wf-workflow"], h["x-lab-wf-action"] = wf, wf_action
    return {"profile_id": "custom_1_tenantdesk", "run_id": run, "sequence_id": run + "-sequence-001", "workflow_id": "t", "step_idx": str(step),
            "case_id": case, "valid_request": valid, "operation_id": op, "actor": actor, "method": method, "path": path, "request_headers": h,
            "request": None, "request_body_sha256": None, "status_code": status, "response": body, "response_sha256": resp_hash}


def run_cov(tmp_path, events):
    log = tmp_path / "events.jsonl"
    log.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    out = tmp_path / "report.json"
    subprocess.run([sys.executable, str(RANGE / "coverage.py"), "--log", str(log), "--out", str(out)], check=True, capture_output=True)
    return json.loads(out.read_text(encoding="utf-8"))["per_app"]["tenantdesk"]


def test_operation_and_pair_coverage(tmp_path):
    r = run_cov(tmp_path, [
        ev(0, "actor-amy", "GET", "/tickets/1002", 403, "get_ticket", obj="ticket-1002", case="AUTHZ-101"),       # cross pair, valid probe
        ev(1, "actor-amy", "GET", "/tickets/1001", 200, "get_ticket", obj="ticket-1001"),                           # amy owns 1001: not a cross pair
        ev(2, "actor-adam", "GET", "/users", 200, "list_users")])
    assert r["operation_coverage"] == round(2 / 26, 4)                                    # get_ticket + list_users of 26 TenantDesk actions
    assert r["pairs_meaningful"] == [1, 84]                                               # 7 actors x 14 addressable objects - 14 owner pairs
    assert r["planted_cases"]["probed"] == 1 and r["planted_cases"]["by_family"]["F1"]["probed"] == 1


def test_invalid_requests_do_not_count(tmp_path):
    r = run_cov(tmp_path, [ev(0, "actor-amy", "GET", "/tickets/1002", 403, "get_ticket", obj="ticket-1002", valid="false")])
    assert r["operation_coverage"] == 0 and r["pairs_meaningful"][0] == 0 and r["valid_sequence_rate"] == 0


def test_provenance_and_safety_counts(tmp_path):
    r = run_cov(tmp_path, [
        ev(0, "actor-amy", "GET", "/tickets/1001", 200, "get_ticket", obj="ticket-1001"),
        ev(1, "actor-amy", "GET", "/tickets/1001", 200, "get_ticket", obj="ticket-1001", resp_hash=None),         # no hash
        ev(2, "actor-amy", "GET", "/docs", 200, None),                                                              # outside the allowlist
        ev(3, "actor-amy", "GET", "/tickets/1001", 500, "get_ticket", obj="ticket-1001")])                          # range error
    assert r["provenance_rate"] == 0.75
    assert r["safety_detail"] == {"outside_allowlist": 1, "http_5xx": 1} and r["safety_gate_violations"] == 2


def test_workflow_step_needs_correct_state_and_role(tmp_path):
    ticket = {"id": 1004, "status": "open"}
    steps = [ev(0, "actor-amy", "POST", "/tickets", 201, "create_ticket", body=ticket, wf="workflow-ticket", wf_action="create_ticket"),
             # a member must not 'start' a ticket (Agent/Admin only) even though the server answered 200
             ev(1, "actor-amy", "POST", "/tickets/1004/transition", 200, "transition_ticket", body={"id": 1004, "status": "in_progress"},
                obj="ticket-1004", wf="workflow-ticket", wf_action="transition_ticket:start")]
    r = run_cov(tmp_path, steps)
    assert r["workflow_coverage"] == 0 and "transition_ticket:start" in r["workflows_uncovered"]["workflow-ticket"]
    steps[1] = ev(1, "actor-adam", "POST", "/tickets/1004/transition", 200, "transition_ticket", body={"id": 1004, "status": "in_progress"},
                  obj="ticket-1004", wf="workflow-ticket", wf_action="transition_ticket:start")
    r = run_cov(tmp_path, steps)
    assert "transition_ticket:start" not in r["workflows_uncovered"]["workflow-ticket"]                       # now valid
    assert "TICKET-T01" not in r["transitions_uncovered"]
