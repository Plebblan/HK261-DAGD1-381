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
| `gateway/start_gateway.py` | Thin launcher for the shared `src.proxy` reverse proxy; there is no app-specific gateway engine or legacy allowlist |
| `run_trace.py` | Replays a trace over HTTP **through the gateway** (stdlib only); `--direct` bypasses it for debugging |
| `coverage.py` | Phase-1 coverage metrics from run-scoped Store traces (`runs/<target>/<run-id>/trace.jsonl`) -> `reports/coverage_report.json` |
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

## Running through the shared OpenAPI-driven proxy

The request path is `run_trace.py -> shared reverse proxy (src.proxy) -> app`.
RunTrace does not implement policy. The shared proxy applies the target-scoped
OpenAPI allowlist, explicit write approval, budgets, kill switch, redaction,
SQLite audit, JSONL trace, and HAR export.

Start the patched lab twins from the repository root:

```bash
TD_ENABLED_FLAWS=NONE SF_ENABLED_FLAWS=NONE \
  docker compose -f lab-apps/docker-compose.yml --profile custom up --build -d tenantdesk shopflow
```

For each app, create a separate run and generate its allowlist from the live
OpenAPI document. TenantDesk example:

```bash
export RUN_ID_TD="$(python -c 'import uuid; print(uuid.uuid4().hex)')"
export RUN_DIR_TD="runs/tenantdesk/$RUN_ID_TD"
mkdir -p "$RUN_DIR_TD"
curl -fsS http://127.0.0.1:8001/openapi.json -o "$RUN_DIR_TD/openapi.json"
python -m src.allowlist.builder \
  --openapi "$RUN_DIR_TD/openapi.json" \
  --config config/tenantdesk/gateway.yaml \
  --output "$RUN_DIR_TD/allowlist.generated.json"
```

Start the proxy in terminal 1:

ShopFlow gets its own run ID and directory:

```bash
export RUN_ID_SF="$(python -c 'import uuid; print(uuid.uuid4().hex)')"
export RUN_DIR_SF="runs/shopflow/$RUN_ID_SF"
mkdir -p "$RUN_DIR_SF"
curl -fsS http://127.0.0.1:8002/openapi.json -o "$RUN_DIR_SF/openapi.json"
python -m src.allowlist.builder \
  --openapi "$RUN_DIR_SF/openapi.json" \
  --config config/shopflow/gateway.yaml \
  --output "$RUN_DIR_SF/allowlist.generated.json"
```

```bash
python lab-apps/custom_1/cyber-range/gateway/start_gateway.py tenantdesk \
  --run-id "$RUN_ID_TD" --run-dir "$RUN_DIR_TD" \
  --allowlist "$RUN_DIR_TD/allowlist.generated.json" \
  --openapi "$RUN_DIR_TD/openapi.json"
```

Run the TenantDesk traces in terminal 2. The exact same run ID and run
directory must be passed to the runner:

```bash
python lab-apps/custom_1/cyber-range/run_trace.py \
  lab-apps/custom_1/cyber-range/traces/trace_td_01_ticket_lifecycle.json \
  lab-apps/custom_1/cyber-range/traces/trace_td_02_document_review.json \
  --run-id "$RUN_ID_TD" --run-dir "$RUN_DIR_TD"
```

Repeat the same process for ShopFlow using port 8002, config
`config/shopflow/gateway.yaml`, and `start_gateway.py shopflow`. Its proxy
listens on 8102; TenantDesk listens on 8101. Run the ShopFlow traces with the
matching run ID and directory:

```bash
python lab-apps/custom_1/cyber-range/run_trace.py \
  lab-apps/custom_1/cyber-range/traces/trace_sf_01_order_fulfilment.json \
  lab-apps/custom_1/cyber-range/traces/trace_sf_02_refund_and_coupon.json \
  --run-id "$RUN_ID_SF" --run-dir "$RUN_DIR_SF"
```

When a trace sequence is complete, stop its proxy with Ctrl-C. The run
directory contains:

```text
runs/<target>/<run-id>/
  run.json
  openapi.json
  allowlist.generated.json
  evidence.sqlite3
  trace.jsonl
  trace.har
  runtrace.json
  runtrace/<trace-id>.json
```

Run coverage from the repository root, passing the two run-local trace logs:

```bash
python lab-apps/custom_1/cyber-range/coverage.py \
  --log "$RUN_DIR_TD/trace.jsonl" \
  --log "$RUN_DIR_SF/trace.jsonl" \
  --evidence-dir runs \
  --fail-on-kpi
```

Then run static and ground-truth checks:

```bash
python lab-apps/custom_1/cyber-range/validate_custom.py
python lab-apps/custom_1/cyber-range/replay_ground_truth.py
python -m pytest tests -q
```

The proxy records both forwarded and blocked requests. Coverage uses only
forwarded requests for operation/workflow/provenance metrics, but reports
gateway denials separately. Anonymous and undocumented denials are retained
in `trace.jsonl`; they are not silently dropped. `--direct` is a debug-only
bypass and must never be used for KPI runs.

Non-read requests require the explicit `X-Range-Approval: true` header and a
configured approval pattern. The approval signal does not authorize
undocumented operations. The target configs keep reset as an explicit extra
method and classify only the synthetic login bootstrap as non-destructive.
All other writes stay disabled until a RunTrace step explicitly requests
approval. The gateway is not the authorization oracle: ground truth and
business-state invariants remain separate inputs used only by evaluation.

## Coverage metrics

Defined in the `coverage.py` docstring (fixed before results; see `docs/GroundTruth_Metrics_Coverage.md`): operation, workflow
(every step valid, state-checked, in one sequence), state-transition, invalid-edge probe, role/object-pair (meaningful and raw
universes), valid-sequence rate, provenance rate, planted/benign case coverage, safety-gate violations. Do not change a
definition after looking at a report; bump `METRICS_VERSION` and record why.
