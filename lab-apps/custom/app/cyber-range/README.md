# Custom mock Cyber Range

Use-case captures are stored one workflow per file in `traces/usecases/`.
Each file preserves actor, UI screen/action, API operation, object reference,
and ordered steps. The runner executes the fixed DSL; the shared reverse proxy
owns policy decisions, request forwarding, and durable audit.

## Run a captured workflow through the shared gateway

Run all commands from the repository root. Start the local API and its
disposable database first. Use a fresh run ID and run directory for every run.

```bash
export RUN_ID="$(python -c 'import uuid; print(uuid.uuid4().hex)')"
export RUN_DIR="runs/custom/$RUN_ID"
mkdir -p "$RUN_DIR"

curl -fsS http://127.0.0.1:8000/openapi-source.json -o "$RUN_DIR/openapi.json"

python -m src.allowlist.builder \
  --openapi "$RUN_DIR/openapi.json" \
  --config config/custom/gateway.yaml \
  --output "$RUN_DIR/allowlist.generated.json"
```

Start the shared reverse proxy in terminal 1:

```bash
python -m src.proxy.run \
  --allowlist "$RUN_DIR/allowlist.generated.json" \
  --config config/custom/gateway.yaml \
  --openapi "$RUN_DIR/openapi.json" \
  --run-id "$RUN_ID" \
  --run-dir "$RUN_DIR" \
  --listen-host 127.0.0.1 --listen-port 8088
```

RunTrace in terminal 2. It sends every API call to the proxy, not directly to
the target:

```bash
python lab-apps/custom/app/runtrace.py \
  --suite lab-apps/custom/app/runtrace_traffic_suite.json \
  --scenario-id workflow-payout-release \
  --allowlist config/custom/gateway.yaml \
  --rso lab-apps/custom/app/cyber-range/model/rso.yaml \
  --run-id "$RUN_ID" --run-dir "$RUN_DIR" \
  --proxy-url http://127.0.0.1:8088
```

The proxy and RunTrace must receive the same `RUN_ID`. Stop the proxy with
Ctrl-C to finalize the JSONL export and run metadata.

## Run-scoped evidence

```text
runs/custom/<run-id>/
  run.json
  openapi.json
  allowlist.generated.json
  evidence.sqlite3
  trace.jsonl
  trace.har
  runtrace.json
```

- `evidence.sqlite3` is the canonical Store record.
- `trace.jsonl` is exported from the Store at proxy shutdown.
- `runtrace.json` contains the ordered DSL steps, assertions, and responses.
- Requests carry run/workflow/sequence/step/actor/operation/case metadata.
- Credentials, authorization headers, and sensitive JSON fields are redacted;
  the raw request and response hashes remain available for integrity checks.

## Safety rules

- Run only against the local disposable lab target.
- Out-of-scope hosts and undocumented routes are default-deny.
- Non-read operations require an explicit `X-Range-Approval: true` signal;
  approval does not bypass the documented-operation allowlist.
- The lab reset endpoint is an explicit configured extra method and is approved
  only when RunTrace sends its control approval header.
- A gateway allow decision is not a vulnerability verdict. Ground truth remains
  outside the gateway and RunTrace inputs.
- Mutable workflows should start from a clean seed and must not run concurrently.

## Configure Custom app vulnerability flags

The Custom API reads `LAB_VULNERABILITIES` at request time. This is a
comma-separated allowlist of vulnerability IDs used by the mock app's
authorization handlers; it is separate from the Gateway allowlist and does
not change Gateway policy.

Create or edit `lab-apps/.env` (the Compose project directory) and set only
the vulnerability cases you want to activate:

```dotenv
# Enable selected lab vulnerabilities
LAB_VULNERABILITIES=AUTHZ-001,AUTHZ-007,AUTHZ-011
```

Recreate the Custom API so the container receives the updated environment:

```bash
docker compose -f lab-apps/docker-compose.yml up -d --force-recreate api
```

Check the API is ready:

```bash
curl -fsS http://127.0.0.1:8000/health
```

Flag behavior:

- Empty or unset `LAB_VULNERABILITIES`: all vulnerability cases are disabled
  (safe baseline).
- A comma-separated list, such as `AUTHZ-001,AUTHZ-007`: only those named
  cases are enabled.
- `LAB_VULNERABILITIES=*`: enables every vulnerability case implemented by
  the Custom mock app. Use only in an isolated, disposable lab.
- IDs are matched exactly; separate multiple IDs with commas and do not add
  spaces inside an ID.

To return to the safe baseline, remove the value or set it empty in
`lab-apps/.env`, then recreate the API container with the same Compose
command. Changing the environment file alone does not update an already
running container.

## Meaning of the `flags` field in trace JSON

Some probe trace files contain a top-level field such as:

```json
"flags": "disabled"
```

This is trace metadata describing the probe's current enablement/intended
status in the trace catalog. It is **not** the same setting as
`LAB_VULNERABILITIES`: changing this field does not activate a vulnerability
inside the API.

The current `runtrace.py` loader selects the trace's `steps` and executes
them; it does not evaluate the top-level `flags` field. Therefore, do not
assume `"flags": "disabled"` prevents execution when a trace is passed
directly with `--scenario`. To control whether a vulnerability is present in
the Custom API, configure `LAB_VULNERABILITIES` as described above. To run a
trace, pass its JSON file explicitly:

```bash
python lab-apps/custom/app/runtrace.py \
  --scenario lab-apps/custom/app/cyber-range/traces/probes/trace_01_access_boundaries.json \
  --allowlist config/custom/gateway.yaml \
  --rso lab-apps/custom/app/cyber-range/model/rso.yaml \
  --run-id "$RUN_ID" --run-dir "$RUN_DIR" \
  --proxy-url http://127.0.0.1:8088
```

For reproducible testing, keep the vulnerability configuration fixed for the
whole run and record the selected IDs with the test results. Use a fresh
database seed/reset before state-mutating traces.

