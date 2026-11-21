# OpenAPI-driven Safety Gateway

The gateway is a Stateful Testing component under `src/`. It is not copied into
or reimplemented by each target application.

## Per-target flow

1. A target adapter/config identifies the target's OpenAPI source and fixed
   upstream base URL. Fetching a remote spec belongs to that adapter; the core
   spec loader consumes a local JSON/YAML document and does not perform network
   access.
2. `src/spec/loader.py` normalizes OpenAPI 3 operations and local references.
   OpenAPI is an API-surface description only; it does not provide roles,
   ownership, authorization truth, or business-state rules.
3. `src/allowlist/builder.py` combines normalized operations with
   `config/<target>/gateway.yaml` and generates a target-specific, hashed
   allowlist. Generated artifacts are run-scoped and must not be hand-edited.
4. `src/gateway/engine.py` evaluates every outbound request. It is transport
   agnostic and never forwards traffic.
5. `src/proxy/addon.py` is the mitmproxy transport adapter. It calls the
   shared engine and only lets a `forwarded` verdict reach the upstream.

The target apps remain independent. The tool must never import from
`lab-apps/`, and it must never read lab ground truth or app policy files.

## Target configs

Initial local target descriptors are provided for:

- `config/custom/gateway.yaml` — Custom mock API, port 8000
- `config/tenantdesk/gateway.yaml` — TenantDesk, port 8001
- `config/shopflow/gateway.yaml` — ShopFlow, port 8002

Each target has an exact host scope, fixed upstream, explicit
`undocumented_policy`, budgets, destructiveness defaults, and approval list.
The configs start in dry-run mode.

## Build an allowlist

After starting the relevant lab app and saving its OpenAPI document locally:

```bash
python -m src.allowlist.builder \
  --openapi path/to/target-openapi.json \
  --config config/tenantdesk/gateway.yaml \
  --output runs/tenantdesk/<run-id>/allowlist.generated.json
```

The current builder intentionally does not fetch OpenAPI URLs. This keeps
network retrieval and app-specific details outside the pure spec loader.

## Safety semantics

- Out-of-scope hosts are blocked by default; `pass_hosts` are exact names only.
- Undocumented operations require an explicit `block`, `hold`, or
  `allow_and_flag` policy. There is no implicit default.
- Documented operations are not automatically authorized. Writes remain
  blocked until classified and enabled or matched by a pre-approved pattern.
- Unknown destructiveness is disabled by default.
- Gateway-generated blocks are distinct from target application responses.
- The policy engine does not own TLS, networking, counters, persistence, or
  response handling; those belong to adapters and supporting modules.
