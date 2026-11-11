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

`docs/openapi.json` is the route contract for both the API dispatcher and the
gateway boundary. It includes the API routes plus the lab-only routes used by
the workflow simulator. Rebuild the gateway's route/method allowlist after
changing the contract:

```sh
python app/build_allowlist.py
```

RunTrace traces are ordered interaction examples. Their evidence records the
observed request/response; traces do not assert expected status or state.

Run the app-scoped Safety Gateway after starting the API. It listens only on
loopback and forwards to the fixed custom API upstream in its profile. RunTrace
must send through the proxy so each request gets an event correlated with the
API audit log by request ID:

```sh
cd app
python gateway.py --serve --profile gateway_profile.json
```

Run one user-journey capture from `app/`; each file is one use case with ordered
actor, screen/action, API operation, and object metadata. The screen names are
conceptual labels because this mock range has no browser frontend. Proxy events
record observed requests and responses without expected-status assertions.

```sh
cd app
python runtrace.py \
  --scenario cyber-range/traces/usecases/workflow-invoice-payment.json \
  --allowlist runtrace_allowlist.json \
  --rso cyber-range/model/rso.yaml \
  --evidence /tmp/invoice-payment-capture.json
```


The proxy writes redacted capture events to `app/runtrace_proxy_events.jsonl`.
`gateway_profile.json` is the per-app runtime profile; `access_policy.yaml` and
`business_state_graph.yaml` are oracle inputs and do not control forwarding.
Use `python runtrace.py --dry-run ...` to validate trace policy without a
running listener or API.

Each use case in `app/cyber-range/traces/usecases/` is independent and should
start from a clean seed when it changes state. The old exploratory probes are
kept in `app/cyber-range/traces/probes/`. Keep each run isolated; all events
share a `run_id`, `workflow_id`, `sequence_id`, and ordered `step_idx` values.
Proxy events include the screen/action/object labels to make user workflows
easier to reconstruct from observed traffic.

For the taxonomy and coverage contract, see
[`../../docs/GroundTruth_Metrics_Coverage.md`](../../docs/GroundTruth_Metrics_Coverage.md).
