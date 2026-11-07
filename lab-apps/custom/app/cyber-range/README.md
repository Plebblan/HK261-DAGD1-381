# Custom mock Cyber Range

This directory contains the app-specific RSO, access policy, state graph,
flaw catalog, seeded objects, workflow definitions, and replayable trace
scenarios. The shared family definitions are in `docs/Taxonomy/families.yaml`.

The `family` value in `ground_truth/ground_truth.yaml` follows the shared IDs:
F1 (same-tenant object authorization), F2 (function authorization), F3
(property authorization), F4 (tenant isolation), and F5 (state-transition
invariants). Vulnerability flags are implemented by the app and disabled by
default. Safe-baseline traces should run with flags disabled; replay a single
case with only its flag enabled when collecting vulnerable-side evidence.

Run from `lab-apps/custom/app` after the local API and MongoDB are up:

```bash
python runtrace.py --scenario cyber-range/traces/trace_01_access_boundaries.json \
  --allowlist runtrace_allowlist.json --rso cyber-range/model/rso.yaml \
  --evidence /tmp/custom-trace-01.json
```

Use the same form for `trace_02_financial_workflow.json` and
`trace_03_ticket_state_and_tenant.json`. Stateful scripts require a clean
seed before each run. The reset endpoint replaces all collections in the mock
seed, including base API data, so only use it with a disposable database. Do
not run state-changing traces concurrently.
