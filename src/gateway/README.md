# OpenAPI-driven Safety Gateway

The gateway is shared code under `src/`; each lab target has only its own
configuration and generated allowlist. OpenAPI describes the API surface, not
authorization, ownership, or business-state truth.

## 1. Install and run the lab targets

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[test]"
docker compose -f lab-apps/docker-compose.yml --profile custom up --build -d
```

Check the target health endpoints:

```bash
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8001/_lab/health
curl -fsS http://127.0.0.1:8002/_lab/health
```

## 2. Create one isolated run and generate its allowlist

Choose a target. This example uses TenantDesk. Each run gets its own directory;
do not reuse a run directory or hand-edit a generated allowlist.

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

python - <<'PY'
import json, os
p = os.environ["RUN_DIR"] + "/allowlist.generated.json"
d = json.load(open(p, encoding="utf-8"))
print("target:", d["target_id"])
print("operations:", len(d["entries"]))
print("allowlist hash:", d["allowlist_hash"])
PY
```

For the other targets, use `TARGET=custom` and fetch
`http://127.0.0.1:8000/openapi-source.json`, or use `TARGET=shopflow` and
fetch `http://127.0.0.1:8002/openapi.json`. Their health endpoints and config
paths are listed above and in `config/<target>/gateway.yaml`.

The builder reads a local OpenAPI JSON/YAML file; it deliberately does not
fetch remote URLs. Configured upstream hosts must match the request host
including the port (for example, `127.0.0.1:8001`).

## 3. Start the proxy

In the same shell, from the repository root:

```bash
mitmdump --listen-host 127.0.0.1 --listen-port 8080 \
  -s src/proxy/addon.py \
  --set "gateway_allowlist=$RUN_DIR/allowlist.generated.json" \
  --set "gateway_config=config/$TARGET/gateway.yaml" \
  --set "gateway_run_dir=$RUN_DIR" \
  --set "gateway_run_id=$RUN_ID"
```

Send test traffic through the proxy from another terminal:

```bash
# Expected: policy decision recorded; if allowed, upstream response returned.
curl -i --proxy http://127.0.0.1:8080 http://127.0.0.1:8001/_lab/health

# An undocumented route is expected to be blocked under the default block policy.
curl -i --proxy http://127.0.0.1:8080 http://127.0.0.1:8001/not-in-openapi
```

Use plain HTTP for this local lab example. HTTPS interception requires installing
and trusting the mitmproxy CA in the test client. Do not disable TLS verification
as a general-purpose workaround.

Stop `mitmdump` with Ctrl-C. Its shutdown hook exports the run's SQLite events
to `trace.jsonl`.

## 4. Run tests and verify the trace

Unit and integration tests:

```bash
python -m pytest tests/gateway tests/allowlist tests/proxy -q
```

After stopping the proxy, verify the trace and SQLite evidence belong to the
same run. These checks compare the event IDs and verdicts in both artifacts:

```bash
python - <<'PY'
import json, os, sqlite3
from pathlib import Path

run_dir = Path(os.environ["RUN_DIR"])
meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
trace = [json.loads(line) for line in (run_dir / "trace.jsonl").read_text(encoding="utf-8").splitlines() if line]
db = sqlite3.connect(run_dir / "evidence.sqlite3")
rows = db.execute(
    "SELECT event_id, run_id, gateway_verdict FROM events WHERE run_id=? ORDER BY rowid",
    (meta["run_id"],),
).fetchall()
trace_ids = [event["event_id"] for event in trace]
db_ids = [row[0] for row in rows]
assert trace_ids == db_ids, (trace_ids, db_ids)
assert all(row[1] == meta["run_id"] for row in rows)
assert [event["gateway_verdict"] for event in trace] == [row[2] for row in rows]
print("run_id:", meta["run_id"])
print("trace events:", len(trace))
print("SQLite events:", len(rows))
print("verdicts:", [row[2] for row in rows])
print("TRACE VERIFIED")
PY
```

Expected run directory:

```text
runs/<target>/<run-id>/
  run.json
  allowlist.generated.json
  openapi.json
  evidence.sqlite3
  trace.jsonl
```

`evidence.sqlite3` is the canonical audit store. A request decision is
committed to SQLite before the addon allows the request upstream; if that
write fails, the addon returns 503 and does not forward. Upstream response
metadata is committed by the response hook. `trace.jsonl` is an export of
those persisted events, not a separate source of truth. Request bodies and
headers are not copied into the trace; Store redaction is applied to persisted
payload fields.

## 5. Safety behavior and limitations

- Out-of-scope hosts are blocked by default; `pass_hosts` are exact host
  entries. The current HTTP addon is not a transparent CONNECT tunnel handler;
  use only the documented HTTP lab path for this example.
- Undocumented operations follow the explicit `block`, `hold`, or
  `allow_and_flag` policy. There is no implicit default.
- OpenAPI presence alone does not authorize writes. Unknown destructiveness is
  disabled unless explicitly classified and approved.
- The initial target configs are dry-run configurations. In dry-run mode a
  policy-permitted request receives a gateway dry-run response instead of
  reaching the target.
- The current adapter records request decisions and response metadata. It does
  not yet enforce every configured rate/concurrency budget; those controls
  must not be considered active until implemented and covered by tests.
- Do not merge this feature branch into `main` without review and explicit
  approval.
