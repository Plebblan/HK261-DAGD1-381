"""Fixed-scenario RunTrace runner and shared DSL for the Gray-box tester.

The planner loop imports the same DSL and calls its methods independently.
RunTrace does not feed candidates to the planner; it executes only its own
immutable scenario steps. Ground truth/planted flags are never loaded here.
"""
from __future__ import annotations
import argparse, json, os, uuid
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any
import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.proxy.client import SafetyGateway, GatewayResult


def _public_result(value: Any) -> Any:
    if is_dataclass(value):
        record = asdict(value)
        # The proxy needs raw bytes to preserve the target response, but they are
        # never part of RunTrace evidence (which could otherwise contain tokens).
        record.pop("response_body", None)
        return record
    return value


# Use synthetic development identities only. Override with environment variables.
ACTORS = {
    "customer_a": {"email_env": "LAB_CUSTOMER_A_EMAIL", "password_env": "LAB_CUSTOMER_A_PASSWORD"},
    "customer_b": {"email_env": "LAB_CUSTOMER_B_EMAIL", "password_env": "LAB_CUSTOMER_B_PASSWORD"},
    "supplier_a": {"email_env": "LAB_SUPPLIER_A_EMAIL", "password_env": "LAB_SUPPLIER_A_PASSWORD"},
    "supplier_b": {"email_env": "LAB_SUPPLIER_B_EMAIL", "password_env": "LAB_SUPPLIER_B_PASSWORD"},
     "support_a": {"email_env": "LAB_SUPPORT_A_EMAIL", "password_env": "LAB_SUPPORT_A_PASSWORD"},
    "admin": {"email_env": "LAB_ADMIN_EMAIL", "password_env": "LAB_ADMIN_PASSWORD"},
    # Aliases used verbatim by workflows.yaml
    "actor-customer-a": {"email_env": "LAB_CUSTOMER_A_EMAIL", "password_env": "LAB_CUSTOMER_A_PASSWORD"},
    "actor-customer-a2": {"email_env": "LAB_CUSTOMER_A2_EMAIL", "password_env": "LAB_CUSTOMER_A2_PASSWORD"},
    "actor-customer-b": {"email_env": "LAB_CUSTOMER_B_EMAIL", "password_env": "LAB_CUSTOMER_B_PASSWORD"},
    "actor-supplier-a": {"email_env": "LAB_SUPPLIER_A_EMAIL", "password_env": "LAB_SUPPLIER_A_PASSWORD"},
    "actor-supplier-b": {"email_env": "LAB_SUPPLIER_B_EMAIL", "password_env": "LAB_SUPPLIER_B_PASSWORD"},
    "actor-support-a": {"email_env": "LAB_SUPPORT_A_EMAIL", "password_env": "LAB_SUPPORT_A_PASSWORD"},
    "actor-admin-a": {"email_env": "LAB_ADMIN_EMAIL", "password_env": "LAB_ADMIN_PASSWORD"},
}

ACTOR_ID_ALIASES = {
    "customer_a": "actor-customer-a", "customer_b": "actor-customer-b",
    "supplier_a": "actor-supplier-a", "supplier_b": "actor-supplier-b",
    "support_a": "actor-support-a", "admin": "actor-admin-a",
}

# Safe baseline scenario: authenticate, inspect self-visible resources, read seeded
# records, and collect status/evidence. No destructive action is in the default trace.
DEFAULT_SCENARIO = [
    {"id": "auth_customer_a", "dsl": "login", "actor": "customer_a"},
    {"id": "list_resources_a", "dsl": "list", "actor": "customer_a", "resource_type": "orders"},
    {"id": "auth_customer_b", "dsl": "login", "actor": "customer_b"},
    {"id": "list_resources_b", "dsl": "list", "actor": "customer_b", "resource_type": "orders"},
]


class DSLExecutor:
    def __init__(self, gateway: SafetyGateway, *, run_id: str | None = None,
                 workflow_id: str = "trace"):
        self.gateway = gateway
        self.run_id = run_id or str(uuid.uuid4())
        self.workflow_id = workflow_id
        self.sequence_id = f"{self.run_id}-sequence-001"
        self.step_idx = 0
        self.tokens: dict[str, str] = {}
        self.results: list[dict] = []
        self.current_actor: str | None = None
        self.assertions: list[dict] = []
        self.last_response_by_step: dict[str, Any] = {}
        self.last_http_result: Any = None

    def _next(self):
        current = self.step_idx
        self.step_idx += 1
        return current

    def login(self, actor: str, *, interaction: dict | None = None) -> dict:
        cfg = ACTORS.get(actor)
        if not cfg: raise ValueError(f"Unknown actor alias: {actor}")
        if self.gateway.dry_run:
            # Placeholder is used only for local policy simulation; never sent to backend.
            token = "DRY_RUN_TOKEN"
        else:
            email, password = os.getenv(cfg["email_env"]), os.getenv(cfg["password_env"])
            # Prefer explicit environment overrides; otherwise use the synthetic RSO registry.
            registry = self.gateway.actor_registry
            actor_row = registry.get(actor) or registry.get(ACTOR_ID_ALIASES.get(actor, ""))
            if not email and actor_row:
                email = actor_row.get("Email")
            if not password and actor_row:
                password = actor_row.get("Password")
            if not email or not password:
                raise RuntimeError(f"Missing credentials: set {cfg['email_env']}/{cfg['password_env']} or provide actor in rso.yaml.")
            step_idx = self._next()
            token = self.gateway.issue_token(actor, email, password, self.run_id,
                                             sequence_id=self.sequence_id, step_idx=step_idx,
                                             workflow_id=self.workflow_id, interaction=interaction)
        self.tokens[actor] = token
        self.current_actor = actor
        return {"actor": actor, "authenticated": True}

    def call(self, actor: str, method: str, path: str, *, body=None, params=None, headers=None, approval=False):
        if actor not in self.tokens: raise RuntimeError(f"Actor {actor} has no session; call login first.")
        step_idx = self._next()
        request_headers = dict(headers or {})
        request_headers["x-lab-step-index"] = str(step_idx)
        request_headers["x-lab-workflow-id"] = self.workflow_id
        request_headers.setdefault("x-lab-valid-request", "true")
        request_headers["x-lab-case-id"] = request_headers.get("x-lab-case-id", "")
        request_headers = {key: value for key, value in request_headers.items() if value != ""}
        result = self.gateway.send(
            actor=actor, method=method, path=path, token=self.tokens[actor],
            json_body=body, params=params, headers=request_headers,
            run_id=self.run_id, sequence_id=self.sequence_id, approval=approval,
            workflow_id=self.workflow_id, step_idx=step_idx,
        )
        record = _public_result(result)
        self.results.append(self.gateway.redact(record))
        return result

    # DSL primitives; object IDs are translated to the app's resource route.
    # Explicit /paths remain supported for operations described by OpenAPI.
    @staticmethod
    def _object_path(object_id_or_path: str) -> str:
        value = str(object_id_or_path)
        return value if value.startswith("/") else f"/lab/v1/resources/{value}"

    def switch_actor(self, alias: str) -> dict:
        if alias not in self.tokens: raise RuntimeError(f"Actor {alias} has no session; call login first.")
        self.current_actor = alias
        return {"current_actor": alias}

    def read(self, actor: str, object_id: str, params=None):
        return self.call(actor, "GET", self._object_path(object_id), params=params)

    def create(self, actor: str, path: str, body):
        return self.call(actor, "POST", path if path.startswith("/") else f"/lab/v1/resources", body=body)

    def update(self, actor: str, object_id: str, body):
        return self.call(actor, "PATCH", self._object_path(object_id), body=body)

    def delete(self, actor: str, object_id: str, approval=False):
        return self.call(actor, "DELETE", self._object_path(object_id), approval=approval)

    def assert_condition(self, name: str, passed: bool, details: dict | None = None):
        item = {"name": name, "status": "passed" if passed else "failed",
                "passed": bool(passed), "details": self.gateway.redact(details or {})}
        self.assertions.append(item)
        return item
    def list_resources(self, actor: str, resource_type=None):
        return self.read(actor, "/lab/v1/resources", {"resource_type": resource_type} if resource_type else None)
    def replay(self, original: dict, as_actor: str):
        return self.call(as_actor, original["method"], original["path"],
                         body=original.get("body"), params=original.get("params"),
                         headers=original.get("headers"))

    @staticmethod
    def _extract_state(payload: Any) -> str | None:
        if not isinstance(payload, dict):
            return None
        for key in ("State", "Status"):
            if isinstance(payload.get(key), str):
                return payload[key]
        for parent in ("Resource", "Invoice", "Payout", "data", "Data"):
            child = payload.get(parent)
            if isinstance(child, dict):
                for key in ("State", "Status"):
                    if isinstance(child.get(key), str):
                        return child[key]
        return None

    def _check_expectations(self, step: dict, result: Any) -> list[dict]:
        if not is_dataclass(result):
            return []  # dry-run cannot prove response assertions
        checks = []
        expected_status = step.get("expect_status")
        if expected_status is not None:
            checks.append(self.assert_condition(
                f"{step['id']}:http_status", result.status_code == int(expected_status),
                {"expected": expected_status, "actual": result.status_code}))
        expected_state = step.get("expect_state")
        if expected_state is not None and result.status_code < 400:
            actual = self._extract_state(result.response)
            checks.append(self.assert_condition(
                f"{step['id']}:state", actual == expected_state,
                {"expected": expected_state, "actual": actual, "response": result.response}))
        return checks

    def execute_step(self, step: dict) -> dict:
        kind, actor = step["dsl"], step.get("actor", "")
        interaction = step.get("interaction", {})
        if kind == "login": value = self.login(actor, interaction=interaction)
        elif kind == "list": value = self.list_resources(actor, step.get("resource_type"))
        elif kind == "switch_actor": value = self.switch_actor(actor)
        elif kind == "assert": value = self.assert_condition(step["name"], step["passed"], step.get("details"))
        elif kind == "replay":
            value = self.replay(step["request"], step["as_actor"])
        elif kind == "request":
            headers = dict(step.get("headers") or {})
            headers.update({
                "x-lab-case-id": step.get("case_id", ""),
                "x-lab-operation-id": interaction.get("operation_id", ""),
                "x-lab-screen": interaction.get("screen", ""),
                "x-lab-user-action": interaction.get("action", ""),
                "x-lab-object-id": interaction.get("object_id", ""),
                "x-lab-usecase-step": str(interaction.get("sequence", "")),
            })
            headers = {key: value for key, value in headers.items() if value != ""}
            value = self.call(actor, step["method"], step["path"],
                              body=step.get("body"), params=step.get("params"), headers=headers,
                              approval=step.get("approval", False))
            self.last_http_result = value
            if step.get("expect_status") is not None or step.get("expect_state") is not None:
                if isinstance(value, dict) and value.get("dry_run"):
                    self.assertions.append({"name": f"{step['id']}:runtime_assertions_skipped",
                                            "status": "skipped", "passed": None,
                                            "details": {"reason": "dry-run does not receive API responses"}})
                else:
                    self._check_expectations(step, value)
        elif kind in {"read", "create", "update", "delete"}:
            value = getattr(self, kind)(actor, step["path"], step.get("body")) if kind in {"create", "update"} else (
                self.delete(actor, step["path"], step.get("approval", False)) if kind == "delete" else self.read(actor, step["path"]))
        else: raise ValueError(f"Unsupported DSL command: {kind}")
        return {"step_id": step["id"], "dsl": kind, "actor": actor,
                "interaction": interaction,
                "result": self.gateway.redact(_public_result(value)),
                "assertions": self.assertions[-2:]}

    def export_evidence(self, output: str):
        payload = {"run_id": self.run_id, "workflow_id": self.workflow_id,
                   "sequence_id": self.sequence_id, "steps": self.results,
                   "assertions": self.assertions}
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")


def _resolve_run_id(run_id: str | None, run_dir: str | Path | None, *, dry_run: bool) -> str:
    """Resolve the proxy-owned run ID without silently inventing a different one."""
    resolved = run_id or os.getenv("RUNTRACE_RUN_ID")
    metadata_path = Path(run_dir) / "run.json" if run_dir else None
    metadata = None
    if metadata_path and metadata_path.is_file():
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Cannot read proxy run metadata at {metadata_path}: {exc}") from exc
        recorded = metadata.get("run_id")
        if not isinstance(recorded, str) or not recorded:
            raise RuntimeError(f"Proxy run metadata has no valid run_id: {metadata_path}")
        if resolved and resolved != recorded:
            raise RuntimeError(
                f"Run ID mismatch before sending traffic: --run-id/RUNTRACE_RUN_ID={resolved!r}, "
                f"but {metadata_path} records {recorded!r}. Use the proxy's recorded run_id."
            )
        resolved = recorded
    if not resolved:
        if not dry_run:
            raise RuntimeError(
                "A shared proxy run ID is required. Pass --run-id with the exact ID used "
                "to start src.proxy.run, or pass --run-dir pointing to that proxy run's "
                "directory containing run.json. Do not generate a new UUID in the runner."
            )
        resolved = str(uuid.uuid4())
    return resolved


def run_trace(scenario: list[dict] | None = None, *, allowlist="config/custom/gateway.yaml",
              rso="lab-apps/custom/app/cyber-range/model/rso.yaml", evidence_out="runtrace_evidence.json", dry_run=False,
              workflow_id="trace", proxy_url="http://127.0.0.1:8088", run_id=None, run_dir=None) -> list[dict]:
    """Execute a pre-authored trace. Does not inspect planner state or ground truth."""
    run_id = _resolve_run_id(run_id, run_dir, dry_run=dry_run)
    gateway = SafetyGateway(
        allowlist, dry_run=dry_run, rso_path=rso,
        proxy_url=None if dry_run else proxy_url, run_id=run_id,
        workflow_id=workflow_id,
    )
    dsl = DSLExecutor(gateway, run_id=run_id, workflow_id=workflow_id)
    if run_dir:
        evidence_out = str(Path(run_dir) / "runtrace.json")
    outputs = []
    try:
        for step in scenario or DEFAULT_SCENARIO:
            outputs.append(dsl.execute_step(step))
        dsl.export_evidence(evidence_out)
        return outputs
    finally:
        gateway.close()


def main():
    parser = argparse.ArgumentParser(description="Run fixed benign RunTrace through Safety Gateway")
    parser.add_argument("--allowlist", default="config/custom/gateway.yaml", help="target gateway config (policy is enforced by the shared proxy)")
    parser.add_argument("--rso", default="lab-apps/custom/app/cyber-range/model/rso.yaml", help="Synthetic actor registry; credentials may be overridden by environment variables")
    parser.add_argument("--scenario", help="JSON file containing a fixed list of DSL steps")
    parser.add_argument("--suite", help="Traffic suite JSON produced from workflows.yaml")
    parser.add_argument("--scenario-id", help="Select exactly one scenario from --suite (run each stateful workflow after a clean reset)")
    parser.add_argument("--evidence", default="runtrace_evidence.json")
    parser.add_argument("--run-id", default=os.getenv("RUNTRACE_RUN_ID"))
    parser.add_argument("--run-dir", help="Run-scoped output directory created by the shared proxy")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--proxy-url", default=os.getenv("RUNTRACE_GATEWAY_URL", "http://127.0.0.1:8088"),
                        help="local Safety Gateway URL (default: %(default)s)")
    args = parser.parse_args()
    workflow_id = "default-safe-trace"
    if args.suite:
        suite = json.loads(Path(args.suite).read_text(encoding="utf-8"))
        scenarios = suite.get("scenarios", [])
        if not args.scenario_id:
            print("Available scenarios (select one with --scenario-id):")
            for item in scenarios:
                print(f"- {item['id']}: {item['name']} (reset_required={item.get('reset_required', False)})")
            return
        selected = next((x for x in scenarios if x["id"] == args.scenario_id), None)
        if selected is None:
            raise SystemExit(f"Unknown scenario id: {args.scenario_id}")
        scenario = selected["steps"]
        workflow_id = selected["id"]
    else:
        loaded_scenario = json.loads(Path(args.scenario).read_text(encoding="utf-8")) if args.scenario else None
        # Trace artifacts may carry metadata beside their ordered `steps` list.
        scenario = loaded_scenario.get("steps", []) if isinstance(loaded_scenario, dict) else loaded_scenario
        if isinstance(loaded_scenario, dict):
            workflow_id = loaded_scenario.get("id", workflow_id)
    outputs = run_trace(scenario, allowlist=args.allowlist, rso=args.rso, evidence_out=args.evidence,
                        dry_run=args.dry_run, workflow_id=workflow_id, proxy_url=args.proxy_url,
                        run_id=args.run_id, run_dir=args.run_dir)
    for item in outputs:
        print(json.dumps(item, ensure_ascii=False, default=str))
    evidence_path = Path(args.run_dir) / "runtrace.json" if args.run_dir else Path(args.evidence)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    failed = [x for x in evidence.get("assertions", []) if x.get("status") == "failed" or x.get("passed") is False]
    skipped = [x for x in evidence.get("assertions", []) if x.get("status") == "skipped"]
    print(f"RunTrace summary: {len(outputs)} steps; {len(evidence.get('assertions', []))} assertions; {len(failed)} failed; {len(skipped)} skipped")
    if failed:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
