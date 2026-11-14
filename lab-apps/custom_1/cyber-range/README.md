# custom_1 Cyber Range (TenantDesk + ShopFlow)

Per-app artifacts for the two synthetic apps in `lab-apps/custom_1`. Shared taxonomy:
`docs/Taxonomy/families.yaml` (F1 same-tenant object, F2 function, F3 property R/W, F4 tenant isolation, F5 state transition).

| Path | Purpose |
|---|---|
| `model/rso_custom.yaml`, `workflows/workflows_custom.yaml`, `seed/objects_custom.json` | RSO model, business workflows, seeded objects |
| `access_policy_custom.yaml` | Intended authorization per operation (role, relation, state, field sets) for both apps, keyed by `METHOD path` like the RSO; lists unplanted deviations DEV-01/02 |
| `business_state_graph_custom.yaml` | State machines and invariants (ticket, document, order, refund, coupon); transitions mirror `workflows_custom.yaml` and the code's tables |
| `flaw_catalog_custom.yaml` | Index of the 31 planted flaws by flag: code location, policy rule, invariant, actors, out-of-scope list |
| `ground_truth/ground_truth.yaml` | **Single source of truth.** 31 planted cases + 12 benign, using taxonomy family ids, oracle types, per-family evidence fields and decisions D1-D5 |
| `ground_truth/planted_cases_custom.csv`, `schema/ground_truth.schema.json` | Flat export of the above (regenerate if the YAML changes) |
| `traces/*.json` | Valid-sequence trace scripts (one per workflow group), same step DSL as `lab-apps/custom` |
| `gateway/` | Per-app profile + allowlist for the existing Safety Gateway engine (`custom/app/gateway.py`, unchanged) and `start_gateway.py` |
| `run_trace.py` | Replays a trace over HTTP **through the gateway** (stdlib only); `--direct` bypasses it for debugging |
| `coverage.py` | Phase-1 coverage metrics from the gateway event logs (`logs/*_gateway_events.jsonl`) -> `reports/coverage_report.json` |
| `rangelib.py` | RSO route matching / object ids shared by the two scripts |
| `replay_ground_truth.py` | Replays every ground-truth case in-process: vulnerable build (only its flag on) vs patched twin |
| `validate_custom.py` | Static consistency checks (model, taxonomy conformance, valid-sequence conformance) |

## Ground truth (taxonomy-based)

Each planted case has exactly one primary `family` (D1) plus optional `secondary_families`, the `oracle_type`
that the taxonomy assigns to that family, and the family's evidence fields (`object_id_origin`,
`role_matrix_cell`, `allowed_field_set` / `restricted_properties`, `actor_tenant_id` / `object_tenant_id`,
`attempted_edge` / `violated_invariant`). Safe outcomes are a set of statuses (D3). `vulnerable_if` is the
machine-checkable form of `observed_when_enabled`.

| Family | Cases |
|---|---|
| F1 | AUTHZ-101, 103, 116, 201, 203 |
| F2 | AUTHZ-108, 109, 110, 206, 207, 208 |
| F3 | AUTHZ-104, 105, 106(R), 107(R), 204, 205, 214(R) |
| F4 | AUTHZ-102, 111, 115, 117, 202, 213 |
| F5 | AUTHZ-112, 113, 114, 209, 210, 211, 212 |

Changes versus the old CSV: families were `BOLA/TENANT/BOPLA/BFLA/WORKFLOW` and several oracle labels did not
match the taxonomy (e.g. TD-03 and TD-15 used `state_invariant`); they now follow `families.yaml`.
Case ids and flags are unchanged. Every case now carries `policy_ref` (rule in the access policy) and, for F5, `invariant_id` / `transition_ref` (state graph). Anonymous (D2) is covered by BENIGN-106 / BENIGN-206.

## Valid-sequence traces

Every request step marked `wf` is one step of `workflows_custom.yaml`; `validate_custom.py` simulates the
state machine (role, pre-state, post-state) so an out-of-order trace is rejected. Ground-truth probes
(`case_id`) are interleaved at the point where the object is in the required state. Traces run against the
patched twin (`ENABLED_FLAWS=NONE`) and expect every probe to be denied; run a single flag to see it fire.

## Running through the Safety Gateway

Traffic path: `run_trace.py -> gateway (127.0.0.1:8101 / :8102) -> app (127.0.0.1:8001 / :8002)`. The existing engine is reused;
only the profile and allowlist differ per app. The engine binds to loopback only, so run it on the host next to the published ports.

```bash
# from lab-apps/ ; the apps run the patched twin
TD_ENABLED_FLAWS=NONE SF_ENABLED_FLAWS=NONE docker compose --profile custom up --build -d tenantdesk shopflow
python custom_1/cyber-range/gateway/start_gateway.py tenantdesk &     # needs fastapi, uvicorn, httpx (custom/requirements.txt)
python custom_1/cyber-range/gateway/start_gateway.py shopflow &

python custom_1/cyber-range/run_trace.py --all --evidence-dir /tmp/custom_1-evidence
python custom_1/cyber-range/coverage.py --evidence-dir /tmp/custom_1-evidence --fail-on-kpi

python custom_1/cyber-range/validate_custom.py
python custom_1/cyber-range/replay_ground_truth.py     # in-process, needs requirements-dev.txt
pytest tests                                           # from the repository root
```

What the gateway enforces for custom_1: default-deny exact method + path-template allowlist (the 48 RSO operations plus
`/_lab/health` and `/_lab/reset`), a token for every authenticated operation, `X-Range-Approval` for destructive operations
(`DELETE` and reset; traces mark those steps `"approval": true`), a per-run request budget (60), per-operation rate limits,
`RUNTRACE_KILL_SWITCH=true` and `RUNTRACE_DRY_RUN=true`. Each forwarded request becomes a redacted event in `logs/`.

Gateway denials are HTTP 403 with a gateway message; `run_trace.py` reports them as `gateway_denied`. Anonymous probes
(BENIGN-106/206) are blocked by the allowlist before the app, so they are safe but do not appear in the event log.
The raw `logs/` and `reports/` are run outputs: generate them from a real run, do not commit stand-in results.

## Coverage metrics

Defined in the `coverage.py` docstring (fixed before results; see `docs/GroundTruth_Metrics_Coverage.md`): operation, workflow
(every step valid, state-checked, in one sequence), state-transition, invalid-edge probe, role/object-pair (meaningful and raw
universes), valid-sequence rate, provenance rate, planted/benign case coverage, safety-gate violations. Do not change a
definition after looking at a report; bump `METRICS_VERSION` and record why.
