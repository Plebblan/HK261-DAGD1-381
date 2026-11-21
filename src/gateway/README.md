# Shared OpenAPI-driven Safety Gateway and RunTrace

There is one policy engine under `src/gateway/` and one transport/audit adapter
under `src/proxy/`. RunTrace is a client/DSL runner; it does not implement
allowlist matching, budgets, forwarding, or audit storage.

```text
OpenAPI + target config
        |
        v
src.allowlist.builder -> runs/<target>/<run-id>/allowlist.generated.json
        |
        v
RunTrace -> local reverse proxy (src.proxy.addon)
                         |
                         +-> src.gateway.engine (default-deny policy)
                         +-> src.store.Store (canonical SQLite audit)
                         +-> target API
                         |
                         +-> trace.jsonl at run shutdown
RunTrace ----------------> runtrace.json (DSL steps/assertions)
```

OpenAPI describes the API surface. It does not establish ownership,
authorization truth, or business-state rules. Those remain target-specific
ground truth and are never read by the policy engine.

## 1. Install and start the lab targets

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[test]"
docker compose -f lab-apps/docker-compose.yml --profile custom up --build -d
```

Check the lab services:

```bash
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8001/_lab/health
curl -fsS http://127.0.0.1:8002/_lab/health
```

## 2. Create a run and build the target allowlist

Every proxy process and RunTrace invocation must use the same run ID and run
directory. Do not reuse a run directory. The proxy creates `run.json` at startup;
RunTrace now treats that file as the authoritative run-ID source when
`--run-dir` is supplied, and rejects a conflicting `--run-id` before sending
any traffic. For safety, a non-dry-run invocation without a proxy-owned run ID
fails immediately instead of generating a new UUID.

TenantDesk example:

```bash
export TARGET=tenantdesk
export RUN_ID="$(python -c 'import uuid; print(uuid.uuid4().hex)')"
export RUN_DIR="runs/$TARGET/$RUN_ID"
mkdir -p "$RUN_DIR"

curl -fsS http://127.0.0.1:8001/openapi.json -o "$RUN_DIR/openapi.json"

python -m src.allowlist.builder \
  --openapi "$RUN_DIR/openapi.json" \
  --config "config/$TARGET/gateway.yaml" \
  --output "$RUN_DIR/allowlist.generated.json"
```

For ShopFlow, use `TARGET=shopflow`, port 8002, and
`http://127.0.0.1:8002/openapi.json`. For the Custom mock, use
`TARGET=custom`, port 8000, and
`http://127.0.0.1:8000/openapi-source.json`.

The builder consumes a local OpenAPI document; it does not fetch remote URLs.
The generated allowlist is immutable run evidence and is copied into the run
directory by the proxy as well.

## 3. Start the shared reverse proxy

Start one proxy process per target/run. TenantDesk uses port 8101, ShopFlow
8102, and Custom 8088.

TenantDesk:

```bash
python lab-apps/custom_1/cyber-range/gateway/start_gateway.py tenantdesk \
  --run-id "$RUN_ID" --run-dir "$RUN_DIR" \
  --allowlist "$RUN_DIR/allowlist.generated.json" \
  --openapi "$RUN_DIR/openapi.json"
```

ShopFlow: change `tenantdesk` to `shopflow`. For the Custom mock:

```bash
python -m src.proxy.run \
  --allowlist "$RUN_DIR/allowlist.generated.json" \
  --config config/custom/gateway.yaml \
  --openapi "$RUN_DIR/openapi.json" \
  --run-id "$RUN_ID" --run-dir "$RUN_DIR" \
  --listen-host 127.0.0.1 --listen-port 8088
```

The launcher uses mitmproxy reverse mode with the configured loopback upstream.
RunTrace talks to the local reverse-proxy URL; it never connects directly to
the lab API unless the explicit debug-only `--direct` flag is used.

## 4. Execute RunTrace through the proxy

For TenantDesk, after starting its proxy:

```bash
python lab-apps/custom_1/cyber-range/run_trace.py --all \
  --run-id "$RUN_ID" --run-dir "$RUN_DIR"
```

For ShopFlow, select the relevant ShopFlow trace file instead of using
TenantDesk traces. The legacy trace runner sends actor, workflow, sequence,
step, case, operation, object, and approval metadata as headers.

For the Custom mock:

```bash
python lab-apps/custom/app/runtrace.py \
  --suite lab-apps/custom/app/runtrace_traffic_suite.json \
  --scenario-id workflow-payout-release \
  --allowlist config/custom/gateway.yaml \
  --rso lab-apps/custom/app/cyber-range/model/rso.yaml \
  --run-id "$RUN_ID" --run-dir "$RUN_DIR" \
  --proxy-url http://127.0.0.1:8088
```

The same `RUN_ID` must be passed to the proxy and RunTrace. If you use two
terminal windows, shell variables are not shared between them. In Terminal 1,
write the ID to a small file before starting the proxy:

```bash
printf '%s\n' "$RUN_ID" > .runtrace-current-id
```

In Terminal 2, you can automatically discover the single active Custom run
from its proxy-owned `run.json` and export both variables. Run this from the
repository root while the Custom proxy is still running:

```bash
eval "$(python - <<'PY'
import json, shlex, sys
from pathlib import Path

active = []
for p in Path("runs/custom").glob("*/run.json"):
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if data.get("status") == "running":
            active.append((p, data))
    except (OSError, json.JSONDecodeError):
        pass

if len(active) != 1:
    print(f"Expected exactly 1 active Custom run, found {len(active)}:", file=sys.stderr)
    for p, data in active:
        print(f"  {p} -> {data.get('run_id')}", file=sys.stderr)
    raise SystemExit(1)

p, data = active[0]
print("export RUN_DIR=" + shlex.quote(str(p.parent)))
print("export RUN_ID=" + shlex.quote(data["run_id"]))
PY
)"

echo "RUN_ID=$RUN_ID"
echo "RUN_DIR=$RUN_DIR"
```

The command intentionally stops if it finds zero or more than one active run;
in that case, check that the proxy is running and that only one Custom run is
active. Then execute RunTrace with those exact values:

```bash
python lab-apps/custom/app/runtrace.py \
  --suite lab-apps/custom/app/runtrace_traffic_suite.json \
  --scenario-id workflow-payout-release \
  --allowlist config/custom/gateway.yaml \
  --rso lab-apps/custom/app/cyber-range/model/rso.yaml \
  --run-id "$RUN_ID" --run-dir "$RUN_DIR" \
  --proxy-url http://127.0.0.1:8088
```

Alternatively, if you used the `.runtrace-current-id` handoff above, load
that ID and set `RUN_DIR="runs/custom/$RUN_ID"`. You may also omit
`--run-id` when `--run-dir` points to the existing proxy run; RunTrace
reads the ID from `run.json`. For a multi-trace
legacy run, `--all` groups the selected traces under that run ID and gives
each trace a distinct sequence ID. Each stateful trace still performs its
configured reset; use a disposable lab database.

## 5. Policy and safety semantics

- Out-of-scope hosts and undocumented operations are blocked by default.
- OpenAPI presence alone does not authorize writes.
- Non-read requests require both a configured approval pattern and the
  per-request `X-Range-Approval: true` signal. The current target configs use
  an explicit wildcard pattern, but the request still must match a documented
  allowlist entry. Reset is separately declared as a target-specific extra
  method.
- Unknown/destructive operations remain blocked without the approval signal.
- Kill switch, request count, per-second rate, and concurrency budgets are
  evaluated by the shared proxy adapter.
- The proxy binds to loopback and only target configs with loopback HTTP
  upstreams are accepted by the launcher.
- `pass_hosts` is intentionally empty for these RunTrace reverse-proxy
  targets. This launcher is not a transparent CONNECT tunnel.
- A gateway decision is an execution-safety decision, not an authorization
  vulnerability verdict. The oracle and ground truth remain outside this path.

## 6. Run-scoped artifacts and trace contract

After RunTrace finishes, its DSL evidence is written to `runtrace.json`.
Stop the proxy with Ctrl-C to finalize:

```text
runs/<target>/<run-id>/
  run.json
  openapi.json
  allowlist.generated.json
  evidence.sqlite3
  trace.jsonl
  trace.har
  runtrace.json
  runtrace/<trace-id>.json       # legacy multi-trace runner
```

`evidence.sqlite3` is canonical. Each request event includes, where available:

- event/run IDs, UTC timestamp, origin, actor;
- workflow, sequence, step, case, operation ID;
- HTTP method, host, path, query, request fingerprint, raw-body SHA-256;
- gateway verdict, reason, matched rule, tags, undocumented flag;
- redacted request and response bodies, response status, elapsed time,
  response SHA-256, and response metadata;
- interaction metadata such as screen, user action, object ID, and use-case step.

Passwords, bearer tokens, cookies, and configured sensitive JSON fields are
redacted before persistence. Hashes are computed from raw bytes before
redaction. Response-side records are committed before the proxy releases the
response to the RunTrace client. If request or response audit persistence fails,
the proxy fails closed with HTTP 503. Upstream transport failures are also
associated with their request event.

`trace.jsonl` and redacted HAR 1.2 (`trace.har`) are exported from SQLite at proxy shutdown; they are not independent event writers. `run.json` records the run ID, target, policy/config
hashes, artifact names, final status, and trace hash.

## 7. Verify that RunTrace traffic was persisted

Stop the proxy first, then compare the JSONL event IDs and verdicts to SQLite:

```bash
python - "$RUN_DIR" <<'PY'
import json, sqlite3, sys
from pathlib import Path

run_dir = Path(sys.argv[1])
meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
trace = [
    json.loads(line)
    for line in (run_dir / "trace.jsonl").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
db = sqlite3.connect(run_dir / "evidence.sqlite3")
rows = db.execute(
    "SELECT event_id, run_id, gateway_verdict FROM events WHERE run_id=? ORDER BY rowid",
    (meta["run_id"],),
).fetchall()
assert trace, "No proxy events were recorded"
assert [event["event_id"] for event in trace] == [row[0] for row in rows]
assert all(row[1] == meta["run_id"] for row in rows)
assert [event["gateway_verdict"] for event in trace] == [row[2] for row in rows]
print("run_id:", meta["run_id"])
print("persisted events:", len(rows))
print("verdict counts:", {
    verdict: sum(row[2] == verdict for row in rows)
    for verdict in sorted({row[2] for row in rows})
})
print("RUNTRACE PROXY TRACE VERIFIED")
PY
```

Test suite:

```bash
python -m pytest tests/gateway tests/allowlist tests/proxy tests/test_custom_1_gateway.py tests/test_coverage_proxy_trace.py -q
```

The GitHub Actions workflow `.github/workflows/gateway-tests.yml` runs the same
suite on pushes to this feature branch and relevant pull requests.
