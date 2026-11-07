# custom_1 Cyber Range (TenantDesk + ShopFlow)

Per-app artifacts for the two synthetic apps in `lab-apps/custom_1`. Shared taxonomy:
`docs/Taxonomy/families.yaml` (F1 same-tenant object, F2 function, F3 property R/W, F4 tenant isolation, F5 state transition).

| Path | Purpose |
|---|---|
| `model/rso_custom.yaml`, `workflows/workflows_custom.yaml`, `seed/objects_custom.json` | RSO model, business workflows, seeded objects |
| `ground_truth/ground_truth.yaml` | **Single source of truth.** 31 planted cases + 12 benign, using taxonomy family ids, oracle types, per-family evidence fields and decisions D1-D5 |
| `ground_truth/planted_cases_custom.csv`, `schema/ground_truth.schema.json` | Flat export of the above (regenerate if the YAML changes) |
| `traces/*.json` | Valid-sequence trace scripts (one per workflow group), same step DSL as `lab-apps/custom` |
| `run_trace.py` | Replays a trace over HTTP against a running app (stdlib only) |
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
Case ids and flags are unchanged. Anonymous (D2) is covered by BENIGN-106 / BENIGN-206.

## Valid-sequence traces

Every request step marked `wf` is one step of `workflows_custom.yaml`; `validate_custom.py` simulates the
state machine (role, pre-state, post-state) so an out-of-order trace is rejected. Ground-truth probes
(`case_id`) are interleaved at the point where the object is in the required state. Traces run against the
patched twin (`ENABLED_FLAWS=NONE`) and expect every probe to be denied; run a single flag to see it fire.

```bash
# from lab-apps/
TD_ENABLED_FLAWS=NONE SF_ENABLED_FLAWS=NONE docker compose --profile custom up --build -d tenantdesk shopflow
python custom_1/cyber-range/run_trace.py --all --evidence-dir /tmp/custom_1-evidence

python custom_1/cyber-range/validate_custom.py
python custom_1/cyber-range/replay_ground_truth.py     # needs requirements-dev.txt
```

Traces call `POST /_lab/reset` first (disposable data only) and must not run concurrently on one app.
