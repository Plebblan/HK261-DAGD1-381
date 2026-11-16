# Architecture (Draft v0.1)

Companion to `workflow.md`. This document fixes module boundaries, interfaces, the event contract, and decision records for the first build iteration. Tags follow `workflow.md`: **[CORE]**, **[OPTIONAL]**, **[DEFERRED]**.

---

## 1. Module map

| # | Module | Input | Output | Depends on | Tag |
|---|---|---|---|---|---|
| 1 | `store` | events, models, findings | SQLite database; JSONL/HAR export | none | CORE |
| 2 | `spec_loader` | OpenAPI document | normalized operations (`operation_id`, route template, params, schemas, servers, security) | none | CORE |
| 3 | `allowlist` (builder) | normalized operations + `config/gateway.yaml` | `allowlist.generated.json` (versioned, hashed) | 2 | CORE |
| 4 | `gateway` (policy engine) | request/response objects, allowlist, config | verdicts (`forwarded`, `blocked`, `dry_run`, `tunneled`), audit events | 3, 1 | CORE |
| 5 | `proxy` (mitmproxy addon) | network traffic | decoded flows passed to the gateway; stored events; HAR export | 4, 1 | CORE |
| 6 | `control_api` + minimal UI | store, gateway state | findings review queue, kill switch (interactive approvals deferred) | 1, 4 | CORE |
| 7 | `capture` (crawler, Playwright) | actor session, scope | HAR with `_actor`/`_fieldAccess` extension | 5 | CORE (later) |
| 8 | `spec_analyzer` | normalized operations | dependency graph, flows, field classification | 2 | CORE (later) |
| 9 | `inference`, `oracle`, `probe generation` | per `workflow.md` | per `workflow.md` | 1, 4, 8 | CORE (later) |

Rule: the tool's code never imports from `lab-apps/` and never reads lab policy or ground-truth files (leakage rule).

Suggested build order: 1, 2, 3, 4, 5, 6, 7, 8.

---

## 2. Engine interface (transport-agnostic)

The gateway engine has no network code and no TLS fields. mitmproxy terminates TLS before the addon runs, so everything downstream sees decoded requests.

```python
@dataclass
class GatewayRequest:
    run_id: str
    mode: Literal["capture", "test"]
    actor: str | None          # from listener port (capture) or caller (test)
    method: str
    scheme: str                # informational only
    host: str
    port: int
    path: str
    query: str
    headers: dict[str, str]
    body: bytes
    origin: Literal["browser", "crawler", "system"]   # who generated it

@dataclass
class Verdict:
    decision: Literal["forwarded", "blocked", "dry_run", "tunneled"]
    reason: str                # e.g. "out_of_scope_host", "not_in_allowlist",
                               # "undocumented_path", "budget_exceeded", "kill_switch"
    rule_id: str | None
    allowlist_hash: str
```

`decide(request) -> Verdict` is a pure function over (request, allowlist, config, counters). The proxy adapter applies the verdict; the engine does not forward anything itself.

---

## 3. Gateway rules

**Direction.** Every outbound request is checked, regardless of who generated it (browser, crawler, or system). Inbound responses are passed without scope checks; the following still apply to them: size and time caps, decompression limits, redaction before storage, and treating content as untrusted data (relevant to Phase 2 prompt-injection risk).

**Redirects.** A 3xx response is passed, but each next hop is a new outbound request and re-enters `decide()`. No client (RunTrace, replay harness, Playwright) follows redirects by itself.

**Blocked requests.**
1. Never forwarded.
2. The caller gets an immediate response with a gateway-block status and a marker header (for example `X-Gateway-Verdict: blocked`).
3. An event is stored with `gateway_verdict = blocked` and the reason.
4. Blocked events are counted separately and are not safety violations. The safety KPI counts requests that reached the upstream outside the allowlist.

**Gateway verdicts are not target verdicts.** The oracle ignores events whose `gateway_verdict` is not `forwarded`, and coverage and detection metrics exclude them. A gateway-generated 403 must never be read as an application deny (D3).

**Out-of-scope hosts.** Default: `block`, in both modes. A host named explicitly in config under `pass_hosts` is tunneled uninspected (TLS not terminated, content not stored; a `tunneled` event records host and byte counts). No wildcards.

**Undocumented paths (shadow-API handling).** An in-scope host with a path or method absent from the OpenAPI document is controlled by `undocumented_policy`:

| Value | Behavior |
|---|---|
| `block` | blocked, event stored with reason `undocumented_path` |
| `hold` | forwarded only if the request matches a pre-approved pattern in config (reason `pre_approved`); otherwise blocked. Event stored either way. No interactive approval in the first iteration |
| `allow_and_flag` | forwarded and flagged `undocumented` for model review |

The key has **no default**. A run with it unset refuses to start. Static assets (non-API GETs on the in-scope host) can be allowed by an explicit path-class rule in capture mode and are logged as `static`.

**Other checks:** per-run request cap, rate and concurrency budget, dry-run, kill switch, destructiveness approval gate (tags from `workflow.md` [C2.4]; before tags exist, writes are allowed only if they match a pre-approved pattern; the rest are blocked), full audit log.

**Out of the gateway's reach.** Requests the target makes on its own (SSRF, webhooks) never pass the gateway. Control them with lab network isolation and egress rules (Docker network, OPNsense), and record this in the threat model.

---

## 4. Proxy modes

| | Capture mode | Test mode |
|---|---|---|
| Proxy type | forward (explicit) proxy, browser points at it | reverse proxy, fixed upstream |
| Driver | human browsing, or crawler | RunTrace, probes, replay |
| Listener | one port per actor, one browser profile per actor | caller supplies actor |
| Policy | scope-based, `undocumented_policy` applies | strict spec-derived allowlist plus budgets |
| Output | events in store, HAR export | events in store |

**Actor listeners.** In capture mode each actor gets its own listener port, allocated dynamically at run start. A launcher creates a browser profile configured with that port and records the mapping in `actor_sessions`. The port gives the `_actor` label. In test mode the caller supplies the actor.

**Import mode (HAR ingestion).** mitmproxy can read external HAR files (verify against the installed version), so DevTools or Burp HARs can be loaded through the same flow path. Imported entries are historical: they are not forwarded to the target and do not count as gateway-forwarded requests. They get `origin = import`, `gateway_verdict = imported`, a source-file reference, and a user-supplied actor; they pass through redaction before storage and are excluded from oracle verdicts and the forwarding/safety KPIs. They still count toward HAR coverage and model inference. The `_actor` and `_fieldAccess` extension fields may not survive mitmproxy's own import/export, so test the round trip.

---

## 5. TLS handling (target runs HTTPS)

- mitmproxy generates a local CA; install it in each actor's browser profile. Keep the CA key out of the repository; the CA is lab-only.
- The lab's upstream certificate may be self-signed (verify against the actual crAPI setup). Prefer trusting that certificate explicitly. If upstream verification must be disabled, restrict the relaxation to the in-scope lab host in config so it cannot apply to another target.
- Intercept only in-scope hosts.
- Compute the raw-body hash before redaction; store only redacted content. Cover this ordering with a test, since interception exposes real tokens and cookies.
- Plain HTTP port, if the lab offers one, may be used for early tests; TLS is still completed in Phase 1.

---

## 6. Store (SQLite)

Separate database file from the target's database. The lab reset replaces target collections and must never touch evidence. WAL mode for concurrent proxy writes and UI reads. Events are append-only.

```sql
CREATE TABLE schema_version (version INTEGER NOT NULL, applied_at TEXT);

CREATE TABLE runs (
  run_id TEXT PRIMARY KEY, mode TEXT, started_at TEXT,
  model_version TEXT, allowlist_hash TEXT, config_hash TEXT,
  seed_id TEXT, undocumented_policy TEXT,
  isolation_mode TEXT                 -- restoration | fresh_objects | read_only
);

CREATE TABLE actor_sessions (
  run_id TEXT REFERENCES runs(run_id), actor TEXT,
  listener_port INTEGER, profile_path TEXT,
  PRIMARY KEY (run_id, actor)
);

CREATE TABLE events (
  event_id TEXT PRIMARY KEY,          -- caller-assigned (UUID/ULID); append is idempotent on it
  -- insertion order within a run is the table's implicit rowid
  run_id TEXT REFERENCES runs(run_id),
  workflow_id TEXT, sequence_id TEXT, step_idx INTEGER,
  ts TEXT, origin TEXT,               -- browser | crawler | system | import
  actor TEXT, operation_id TEXT,      -- operation_id null if undocumented
  method TEXT, host TEXT, path TEXT, query TEXT,
  gateway_verdict TEXT,               -- forwarded | blocked | dry_run | tunneled | imported
  gateway_reason TEXT, rule_id TEXT,
  status INTEGER,                     -- null when not forwarded
  valid_request INTEGER,
  request_redacted TEXT, response_redacted TEXT,   -- JSON, size-capped
  raw_body_hash TEXT,                 -- hash of unredacted request body
  request_fingerprint TEXT,           -- canonical method/path/query/header/body
  response_hash TEXT,
  normalized_hash TEXT, normalization_version TEXT,
  before_state_hash TEXT, after_state_hash TEXT,
  case_id TEXT, tag TEXT, undocumented INTEGER DEFAULT 0
);
CREATE INDEX ev_run ON events(run_id, step_idx);
CREATE INDEX ev_actor_op ON events(actor, operation_id);
CREATE INDEX ev_verdict ON events(gateway_verdict);

CREATE TABLE model_versions (version TEXT PRIMARY KEY, created_at TEXT,
  reason TEXT, payload TEXT);             -- immutable, frozen models
CREATE TABLE findings (finding_id TEXT PRIMARY KEY, run_id TEXT,
  family TEXT, verdict TEXT,              -- violation | safe | needs_review
  evidence TEXT, reason_code TEXT, review_state TEXT, reviewer_note TEXT);
```

Import/export: HAR and JSONL remain interchange formats; imported files keep a source-file reference for provenance. Optional: a hash chain over the audit log for tamper-evidence.

### 6.1 Store adapter

All database access goes through one narrow `Store` class. SQL and `sqlite3` appear only inside it, so a later backend change means rewriting the adapter only.

```
src/store/
  models.py     # dataclasses Run, Event, Finding (the field contract)
  store.py      # Store (SQLite implementation, the only place with SQL)
  schema.sql    # DDL and schema_version
  export.py     # JSONL/HAR export, JSONL import (uses Store only)
tests/store/test_store.py   # behavior tests against the Store API
```

Methods (add only when a module needs one; no generic `query(sql)`):
`create_run`, `append_event`, `append_events` (atomic batch), `get_events(run_id, actor=, operation_id=, verdict=, limit=)`, `put_model` (immutable), `get_model`, `upsert_finding`, `list_findings(run_id, review_state=)`, `close`.

Rules:
1. Callers assign `event_id`; `append_event` is idempotent on it (`INSERT OR IGNORE`).
2. Events and model versions are append-only; `put_model` raises if the version exists.
3. The store receives only redacted events. The raw-body hash is computed before redaction, and that order is enforced at the proxy boundary, not in the adapter.
4. WAL mode and a busy timeout are on. Writes go through a queue and a single writer thread, off the proxy's request path.
5. Timestamps are ISO UTC strings; body fields are size-capped; no ORM; parameterized SQL only.
6. Events come back in insertion order within a run.

Tests use a temp file or `:memory:` database and cover idempotent append, atomic batches, ordering, filters, immutable models, and a concurrent write/read check. The same file serves as the acceptance test if the backend changes.

---

## 7. Configuration (`config/<target>/gateway.yaml`, sketch)

```yaml
scope:
  in_scope_hosts: ["localhost:8443"]
  out_of_scope_default: block
  pass_hosts: []                    # explicit hosts tunneled uninspected; no wildcards
undocumented_policy: null           # REQUIRED: block | hold | allow_and_flag
approved_patterns: []              # pre-approved requests for `hold` and for writes before tags exist
                                   # e.g. {method: POST, path: "/api/v1/orders", actor: user_a}
extra_methods:                      # explicit additions beyond the spec (e.g. calibration, BFLA)
  - {host: "localhost:8443", method: "DELETE", path: "/api/v1/{any}", note: "method-tamper probe"}
budgets:
  max_requests_per_run: 5000
  rate_per_second: 10
  max_concurrency: 2
destructiveness:
  enabled_tags: [read, create, mutate, advance]
  disabled_tags: [terminal, session_affecting, unknown]
tls:
  upstream_trust: "config/<target>/certs/lab-upstream.pem"   # preferred over disabling verification
dry_run: false
logging:
  level: INFO                       # DEBUG adds detail but is still redacted
  max_bytes_per_file: 10485760      # size-based rotation within a run
```

`allowlist.generated.json` is generated by the tool, versioned, hashed, never hand-edited, and stored per run under `runs/<target>/<run_id>/` (not in `config/`). The exact config used is also copied there as `config.snapshot.yaml`. Spec-derived entries and config `extra_methods` are kept visibly separate in the file.

---

## 8. Decision records

**DR1: SQLite for events and models.** Concurrent proxy writes and UI reads, cross-run queries, Phase 2 aggregates over 10+ seeds. No server needed; one file ships in the reproducibility package. Access goes through a narrow `Store` adapter (section 6.1), so a backend change means rewriting only the adapter. Cost of reversing: low (JSONL/HAR export retained). Rejected: JSON files (whole-file rewrites, concurrency), Postgres/Mongo (overkill now).

**DR2: mitmproxy as the proxy engine.** Python, forward and reverse modes, addon API, TLS interception, intercept/hold, existing web UI. Reduces custom work to the gateway addon, actor labeling, the store writer, and the review UI. Verify HAR import/export and the extension-field round trip before committing. Rejected: ZAP (Java), Burp (closed), writing a proxy from scratch.

**DR3: Gateway engine separate from the proxy adapter.** Pure policy function, unit-testable, shared by capture mode, test mode, crawler, and RunTrace. Supports the KPI "100% of requests through the gateway" in every path.

**DR4: Two proxy modes (forward capture, reverse test).** Human browsing needs a forward proxy; automated runs benefit from a fixed upstream that callers cannot override.

**DR5: Direction-based scope with explicit gateway verdict.** Outbound checked, inbound passed; blocked requests recorded with their own verdict so the oracle cannot mistake them for application denies.

**DR6: No default for `undocumented_policy`.** Shadow-API handling is a deliberate per-run decision, not an implicit default.

**DR7: TLS terminated in the proxy adapter only.** Core modules see decoded requests; trust of the lab upstream is explicit and host-scoped.

**DR8: Spec parsing split.** A thin `spec_loader` first (needed by the allowlist builder); the heavy analyzer later on top of it.

**DR9: Imported HAR is ingestion, not traffic.** Imported entries are stored with their own origin and verdict, redacted, and excluded from oracle verdicts and forwarding/safety KPIs. They still feed coverage and inference.

**DR10: Approvals are pre-configured.** No interactive hold in the first iteration; a request matching a pre-approved pattern is forwarded, anything else is blocked. The approved set is part of the config hash recorded with each run. Cost of reversing: low (an interactive queue can be added over the same engine).

---

## 9. Open questions

**Resolved**
- Held requests are approved only by pre-configured patterns (DR10).
- Out-of-scope default is `block`; named hosts may be passed (tunneled).
- Actor listener ports are allocated dynamically, recorded in `actor_sessions`.
- mitmproxy can import external HAR files (verify version support); imports are ingestion (DR9).

**Open**
- A3. Does crAPI's compose use a self-signed certificate, and does it also expose a plain-HTTP port? (to be checked on the range)
- A4. Is a custom HAR exporter needed? Decide after testing whether the extension fields survive mitmproxy's import/export; the store is the source of truth either way.
- A6. Granularity of `approved_patterns` (method + path template + actor?), and whether wildcards in path templates are allowed.
- A7. Are `tunneled` events logged (host and byte counts only), or not logged at all?
- A8. Imported HARs that mix several users in one file: is one actor label per file enough, or must the import accept a mapping from token/cookie to actor?

---

## 10. Pending: state-restoration trigger (PROPOSED, not adopted)

Linked to `workflow.md` P1 (pending supervisor decision). No other module depends on it; the build order in section 1 is unchanged until it is resolved.

**Idea (optional).** Each target app may provide its own state-restoration feature. If the `state_restoration` key is absent, the runner is not started and the default no-trigger pipeline (`workflow.md` section 12) applies; the run record stores the resulting `isolation_mode`. The tool contains only a thin `restoration` runner: it invokes the declared trigger, waits for the ready check, and verifies the result through the API. It never reads or parses the seed or the restoration process.

**Config sketch (not final)**

```yaml
state_restoration:
  trigger: {type: command, value: "scripts/restore.sh"}   # or {type: http, value: "POST /__lab/reset"}
  timeout_s: 120
  ready_check: "GET /health"
  reset_granularity: per_sequence      # per_probe | per_sequence | per_batch
  checkpoints: false
```

**Behavior**
- `http` triggers go through the gateway as allowlisted `control`-class requests (not test steps, excluded from coverage and metrics). `command` triggers run in a local runner outside the gateway: declared command only, local lab host only, logged, subject to the kill switch.
- Trigger output is kept for exit status and logs, never parsed.
- After each restoration: ready check, actor re-login and liveness check, then a normalized-hash comparison of reference objects against the baseline snapshot. A mismatch records `reset_failure`; the run's affected tests are not trusted.
- Run record gains `reset_count`, `reset_failures`, and total reset time.

**DR11 (PROPOSED): state restoration is an opaque per-app trigger.** The tool does not parse seed data, so it cannot use it as model input or ground truth. Pending supervisor answers to the questions in `workflow.md` P1. Cost of reversing: low (the runner is a thin module).

---

## 11. Repository layout

Status tags: **[NOW]** first iteration, **[LATER]** after the first iteration, **[PENDING]** depends on a supervisor decision, **(existing)** already in the repository.

```
repo/
├── README.md
├── pyproject.toml
├── .gitignore                       # runs/, .env, config/*/certs/*.key, *.db
│
├── config/                          # provided in advance, one folder per target
│   └── <target>/
│       ├── gateway.yaml             # scope, undocumented_policy, budgets, destructiveness,
│       │                            #   approved_patterns, tls, state_restoration (optional)   [NOW]
│       ├── inventory.yaml           # hosts, actors (credential SOURCES, no secrets)           [NOW]
│       └── certs/
│           └── lab-upstream.pem     # public certificate only; private keys are never committed
│
├── src/                             # the tool; never imports lab-apps/ or eval/
│   ├── cli.py                       # entry points: build-allowlist, proxy, import-har, run  [NOW]
│   ├── common/                      # shared, dependency-free                                  [NOW]
│   │   ├── types.py                 #   GatewayRequest, Verdict
│   │   ├── config.py                #   config loading and validation (undocumented_policy required)
│   │   ├── hashing.py               #   raw-body hash, canonical fingerprint, response hash
│   │   ├── redaction.py             #   redaction rules (hash is computed before this runs)
│   │   ├── ids.py                   #   event_id / run_id generation
│   │   └── logging.py               #   component loggers, redaction filter, per-target log directory
│   ├── store/                       # SQLite adapter (section 6.1)                              [NOW]
│   │   ├── models.py  store.py  schema.sql  export.py
│   ├── spec/
│   │   ├── loader.py                #   thin loader: $ref resolution, operation_id, templates    [NOW]
│   │   └── analyzer/                #   dependency graph, flows, field classes                   [LATER]
│   ├── allowlist/
│   │   └── builder.py               #   spec operations + config -> allowlist.generated.json     [NOW]
│   ├── gateway/                     # pure policy engine, no network code                       [NOW]
│   │   ├── engine.py                #   decide(request) -> Verdict
│   │   ├── rules.py  budgets.py  audit.py  kill_switch.py
│   ├── proxy/                       # mitmproxy adapter                                         [NOW]
│   │   ├── addon.py                 #   calls the gateway, writes events via a queue
│   │   ├── modes.py                 #   capture (forward) / test (reverse)
│   │   ├── actors.py                #   dynamic listener allocation, actor_sessions
│   │   ├── har_import.py            #   origin=import, verdict=imported
│   │   └── har_export.py            #   only if extension fields do not round-trip
│   ├── restoration/                 # optional trigger runner (P1)                              [PENDING]
│   │   └── runner.py
│   ├── control/                     # FastAPI control API + minimal UI                          [LATER]
│   │   ├── api.py   (findings queue, kill switch)
│   │   └── ui/
│   ├── capture/                     # crawler as HAR capture assistant                          [LATER]
│   │   ├── launcher.py              #   browser profile per actor, pointed at its listener port
│   │   ├── crawler.py
│   │   └── field_access.js          #   init script recording which JSON properties the page reads
│   ├── inference/                   # GET-first classification, footprints, tags, exposure     [LATER]
│   ├── planting/                    # seed planting, HAR templates                              [LATER]
│   ├── model/                       # RSO model, state graph, freeze/versioning                 [LATER]
│   ├── probes/                      # calibration + template mutation for F1-F5                 [LATER]
│   └── oracle/                      # differential, property-policy, state-invariant            [LATER]
│
├── eval/                            # benchmark evaluation; reads ground truth AFTER runs       [LATER]
│   ├── join_ground_truth.py         #   the only place that touches lab ground truth
│   └── metrics.py                   #   coverage, precision/recall, planting coverage
│
├── tests/
│   ├── test_boundaries.py           # fails if src/ imports lab-apps/ or eval/                  [NOW]
│   ├── store/  common/  allowlist/  gateway/  proxy/                                            [NOW]
│   └── test_custom_cases.py         # (existing) lab-app ground-truth replay; consider tests/lab/
│
├── runs/                            # gitignored: tool outputs, kept separate from the target systems
│   └── <target>/
│       ├── store.db                 # SQLite; one database per target, runs table inside
│       ├── ca/                      # generated proxy CA, reused across runs so browser profiles trust it once
│       ├── logs/                    # system debug logs of the most recent run only (see 11.1)
│       │   ├── run_id.txt           #   which run these logs belong to
│       │   └── proxy.log  gateway.log  store.log  ...   # one file per component
│       └── <run_id>/
│           ├── allowlist.generated.json   # exact allowlist used; its hash is in the run record
│           ├── config.snapshot.yaml       # exact config used, secrets excluded; hash is in the run record
│           └── exports/                   # HAR, JSONL
├── scripts/                         # dev helpers (start proxy, generate allowlist)
│
├── lab-apps/                        # (existing) the target systems; the tool does not import them
│   └── custom_1/ ...
└── docs/                            # (existing) taxonomy, survey, research gaps, plans
    ├── workflow.md                  # this workflow (new)
    ├── architecture.md              # this document (new)
    └── Taxonomy/ ...
```

Notes
- `src/common/` is the only package every other module may import; it has no dependencies of its own.
- The leakage rule is enforced by `tests/test_boundaries.py`, not only by convention.
- Credentials come from environment variables or an untracked `.env`; `inventory.yaml` stores only where a credential comes from.
- The existing `src/README.md` placeholder can be replaced by the top-level README.

### 11.1 System logs

- **Location:** `runs/<target>/logs/`, one file per component (`proxy.log`, `gateway.log`, `store.log`, and so on), plus `run_id.txt` naming the run the logs belong to.
- **Scope:** the most recent run against the target only. The directory is cleared when the next run starts, so a crashed run's logs survive until then. Files rotate by size within a run.
- **Purpose:** debugging, not evidence. The evidence record is the `events` table in `store.db`. The oracle never reads logs, and anything needed to reproduce a result must be in the database or the run folder, not the logs.
- **Redaction:** logs go through the same redaction as stored events: no tokens, cookies or raw bodies, even at DEBUG level. Log lines carry `run_id`, `event_id` and `operation_id` so a line can be tied to a stored event.
- **Setup:** logging is configured by `src/common/logging.py` from the `logging` block in `gateway.yaml`. `runs/` is gitignored.
- **Open:** keep the previous run's logs as `logs.prev/` for comparison, or only the latest?