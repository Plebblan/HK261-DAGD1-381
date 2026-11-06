# Inlanefreight API mock and custom authorization range

This folder contains the FastAPI/MongoDB mock target. The root compose file is
`../docker-compose.yml`; run commands from `lab-apps/`:

```sh
docker compose up --build -d
```

The API is available on `http://localhost:8000`. See [BACKEND_API.md](BACKEND_API.md)
for seeded sign-in accounts and API examples.

## Cyber Range

The app-specific model, policy, state graph, flaw catalog, seed objects, ground
truth, workflows, and traces are under `app/cyber-range/`. Ground truth follows
the shared F1–F5 taxonomy and contains 30 planted cases plus 8 benign cases.
Planted vulnerability flags are disabled by default.

Run the app-scoped Safety Gateway after starting the API. It listens only on
loopback and forwards to the fixed custom API upstream in its profile. RunTrace
must send through the proxy so each request gets an event correlated with the
API audit log by request ID:

```sh
cd app
python gateway.py --serve --profile gateway_profile.json
```

In a second terminal, run one ordered trace:

```sh
cd app
python runtrace.py \
  --scenario cyber-range/traces/trace_01_access_boundaries.json \
  --allowlist runtrace_allowlist.json \
  --rso cyber-range/model/rso.yaml \
  --evidence /tmp/custom-trace-01.json

#venv
python runtrace.py \
  --proxy-url http://127.0.0.1:8088 \
  --scenario cyber-range/traces/trace_01_access_boundaries.json \
  --allowlist runtrace_allowlist.json \
  --rso cyber-range/model/rso.yaml \
  --evidence /tmp/custom-trace-01.json
```


The proxy writes redacted capture events to `app/runtrace_proxy_events.jsonl`.
`gateway_profile.json` is the per-app runtime profile; `access_policy.yaml` and
`business_state_graph.yaml` are oracle inputs and do not control forwarding.
Use `python runtrace.py --dry-run ...` to validate trace policy without a
running listener or API.

Repeat with `trace_02_financial_workflow.json` or
`trace_03_ticket_state_and_tenant.json`. Reset/reseed the lab fixtures before
each stateful trace. Keep each trace run isolated; traces share one `run_id`,
`workflow_id`, `sequence_id`, and ordered `step_idx` values in the audit log.
Use one `LAB_VULNERABILITIES` flag at a time for vulnerable-side evidence, then
return to the default safe configuration.

For the taxonomy and coverage contract, see
[`../../docs/GroundTruth_Metrics_Coverage.md`](../../docs/GroundTruth_Metrics_Coverage.md).
