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
