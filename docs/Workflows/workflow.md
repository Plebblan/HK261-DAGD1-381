# Stateful Web/API Authorization Testing: System Workflow (Draft v0.1)

Status: DRAFT for review and audit. Scope is flexible; every module carries a tag:

- **[CORE]** needed for the Phase 1 deliverable
- **[OPTIONAL]** implement if time allows; the design must not depend on it
- **[DEFERRED]** Phase 2 or later (AI planner/ranker, ML, HITL effectiveness study)

---

## 1. Principles

1. **Two kinds of state machine, never mixed.**
   - *Ground-truth model*: hand-written, lives with the Cyber Range, used only to score results. **Never an input to the tool.**
   - *Inferred model*: built by the tool from its inputs. Every element carries provenance and a status.
2. **Observed is not normative.** An observation can propose a rule; it cannot promote it. Promotion requires probe evidence or human confirmation.
3. **Build phase and probe phase are separate.** The model is frozen and versioned before probing. Probes never update it.
4. **A violation needs effect evidence, not just a status code.** See section 7.
5. **Unknown is not deny.** Missing knowledge produces `needs_review`, never a guess.
6. **Everything runs behind the Safety Gateway** (allowlist, budgets, dry-run, kill switch, audit log, reset).
7. **Phase 1 is deterministic.** Test generation is template mutation from the taxonomy, not fuzzing and not ML.
8. **Every HAR is untrusted input.** It is parsed defensively (size limits, no execution) and is never policy truth. Its job is to reveal real sequences and undeclared parameters/fields.
9. **Isolation beats ordering.** Ordering operations by destructiveness saves re-planting, but after any probe with observed effect the affected object is reset or re-planted.

---

## 2. Inputs

| Input | Format | Provides | Does not provide | Tag |
|---|---|---|---|---|
| OpenAPI document | JSON/YAML | Operations, schemas, params, security schemes/scopes, declared success and error responses, examples, `readOnly`/`writeOnly`, `additionalProperties` | Roles, ownership, business rules, forbidden transitions | CORE |
| HAR traffic | `.har` files, or passive proxy capture during manual interaction | Valid real sequences, ID flow between requests, per-session identity, observed status/field changes, hidden preconditions satisfied in practice | Anything the operator did not exercise | CORE |
| Environment inventory | *Proposed redefinition* (see below) | Actors, in-scope hosts, optional declared seed objects | Policy, state rules | CORE (minimal) |
| HAR from frontend replay (capture assistant) | HAR 1.2; optionally with underscore-prefixed extension fields (`_actor`, `_fieldAccess`) | Extra valid sequences per actor UI (more coverage); with the extension, the allowed field set per actor/route | Authorization truth; reading is not displaying | CORE (replay needs a live app; a plain HAR is still accepted) |
| Database read adapter | Read-only connection | Before/after state readback; objects that cannot be created via API | Policy | OPTIONAL |

**Inventory (proposed definition).** The original description treats inventory as recon output. Since recon is out of scope and the target is an authorized environment, redefine it as an *environment inventory*:

```yaml
hosts:            # feeds the Safety Gateway allowlist
  - base_url: http://localhost:8000
    allowed_paths: ["/api/"]
actors:           # feeds actor switching
  - label: user_a
    role: customer        # optional, may be unknown
    tenant: t1            # optional
    credential_source: login_flow | env_var | har_session
  - label: anonymous
seed_objects: []  # optional, declared only
```

Open question Q1: where does actor identity come from: inventory, one HAR per actor, or both?
-> Inventory, input HAR is not expected to fully cover the identities, but rather from inventories including sessions, and their related attribute (this should be trusted).

#### P1 (PENDING supervisor decision): state-restoration feature

**Status: proposal, not adopted. Nothing in the build depends on it yet.** Reported to the supervisor; to be resolved later.

**Proposal.** Each target application ships a *state-restoration feature*, customized per app (for example: recreate the container from a clean image and re-run the app's own seed/restore). The testing system treats it as an **opaque trigger**. It never reads, parses, or depends on the seed or on how restoration works, so nothing in the tool can use it as model input or ground truth.

**What the tool sees (configuration only)**

```yaml
state_restoration:
  trigger: {type: command | http, value: "..."}   # declared, never composed by the tool
  timeout_s: 120
  ready_check: "GET /health"                       # optional
  reset_granularity: per_sequence                  # per_probe | per_sequence | per_batch
  checkpoints: false                               # optional extension, see 2 below
```

- `command` triggers run in a local runner outside the HTTP gateway. `http` triggers pass through the gateway as an allowlisted `control`-class request, not counted as a test step or in coverage.
- The trigger's output is kept for exit status and logging only. It is never parsed as data.

**Optional by design.** The `state_restoration` key may be omitted. Without it, the tool runs the **default pipeline** discussed earlier: it cannot assume resettability, so it uses fresh-object isolation (plant new objects per test, tag tool-created data, dirty tracking, re-baseline after inference, self-contained sequences, actor liveness and identity checks; see section 12) and falls back to passive capture plus read-only classification, with writes going to `needs_review`, where planting is impossible. Verdict logic is identical in every mode; only the isolation mechanism differs. Each run records `isolation_mode` (`restoration`, `fresh_objects`, `read_only`) so results from different modes are not compared unknowingly.

**What the tool still does, black-box**
1. **Verify restoration through the API.** After the trigger: ready check, actor re-login and liveness check (restored accounts may have fresh tokens), re-read reference objects and compare normalized hashes with the baseline snapshot. A mismatch is a `reset_failure` (feeds the state-reset-failure KPI) and the affected tests are not trusted.
2. **Plan around what restoration returns.** Restoration returns the application to its pre-test state, which does not contain objects the tool planted. The per-test flow becomes restore, plant, probe, read back, and planting requests count toward budgets. If the app's feature also supports named checkpoints (snapshot after planting), the tool can restore to that checkpoint instead; this is optional and depends on the app.
3. **Determinism requirement on the app's side.** Restored state needs stable account identities, and ideally stable seeded object IDs; if IDs are regenerated, the frozen model's references to seeded objects break (tool-planted objects are re-created anyway).
4. **Cost.** Restore time counts toward time metrics; `reset_granularity` controls how often it runs.

**Cautions**
1. **Safety.** A `command` trigger executes outside the gateway: only the declared command, local lab host only, logged, subject to the kill switch. The tool never constructs commands.
2. **No leakage by construction.** The tool does not ingest the hook's output or the seed, so ownership and policy remain inferred (RQ1) and held-out ground truth stays separate.
3. **Per-app work.** Each target needs its own restoration feature. Targets without one fall under the lower reset tiers (see section 12).
4. **Fair comparison.** The benchmark uses the same restoration for every configuration.

**Declaring it.** A trigger is small configuration, closer to "how to reach the environment" than to a data input, so it fits the environment inventory without adding a fourth input. Whether the supervisor agrees is open.

**Questions for the supervisor**
- Is a restoration trigger acceptable as part of the environment inventory/configuration, given that the declared inputs are OpenAPI, HAR and inventory?
- Is the restoration feature part of the tool's contract, or only of the benchmark harness?
---

## 3. Pipeline overview

```
 OpenAPI ─┐
 HAR ─────┼─> [A] Ingest & normalize
 Inventory┘            │
                       v
              [B] Static model (operations, dependency graph, flows)
                       │
                       v
              [C] Seed planting & workflow capture   (uses [B] + HAR templates)
                       │
                       v
              [C2] Inference phase: GET-first classification, effect footprints,
                   destructiveness tags, field exposure analysis
                       │
                       v
              [D] Model synthesis (RSO + state graph, evidence-tiered) ──> FREEZE vN
                       │
                       v
              [E] Calibration probes (learn allow/deny signatures)
                       │
                       v
              [F] Probe generation (template mutation) ──> [G] Gateway ──> target
                       │                                         │
                       v                                         v
              [H] Oracle evaluation <───── evidence ───────── [I] Evidence store
                       │
                       v
              [J] Verdict: violation | safe | needs_review ──> [K] Report / HITL queue
```

---

## 4. Stage details

### [A] Ingest & normalize [CORE]
- Parse OpenAPI; assign a stable `operation_id` per method + route template.
- Parse HAR; map each request to an operation by template matching; label each entry with an actor.
- Redact credentials before persistence; keep tokens in memory only.
- Output: normalized operation inventory and normalized event list.

### [B] Static model [CORE]
1. **Dependency graph** (producer to consumer): from response schemas to later path/body/query params, using name/type matching, OpenAPI `links`, and HAR evidence (a real trace confirms which response field fed which request).
2. **Flow enumeration.** A *flow* is a path in the dependency graph from a root node (no unmet dependency) to a terminal node. Flows are enumerated for every root-to-terminal path, deduplicated by operation sequence. Flows seen in HAR are marked `observed`; spec-derived ones are `candidate`. Flows are the unit for operation ordering ([C2.4]) and for the optional frequency feature ([C2.5]).
3. **Field classification** per resource schema: user-writable, server-controlled, ownership-bearing (exposure is analyzed in [C2.5]).
3. **Declared-behavior hints**: security requirements per operation, declared 401/403/404 responses. Treat as weak priors only.

### [C] Seed planting & workflow capture [CORE]
Goal: obtain objects with *known owner and tenant*, and valid workflow orderings.

1. **HAR templates (core).** Captured valid sequences are replayed per actor to create objects. These already satisfy hidden preconditions.
2. **Producer-consumer planting (core).** For creatable resources not covered by a template, build a chain from [B], fill bodies from schema examples, enums, and values learned from earlier responses.
3. **Runtime-feedback expansion (core; executed as part of [C2]).** Try uncovered operations against planted objects and classify the response:
   - success: record a transition observation
   - 400/409: unmet precondition; queue after another operation
   - 401/403/404: possible access boundary; record only
4. **Coverage report (core).** Operations that could not be planted are marked `unplanted`. Do not guess.
5. **DB ingestion (optional).** Only for non-creatable objects, read-only.

Known limits: data-/time-dependent rules, cross-actor handoffs without an actor with the right role, admin-provisioned data.

### [C2] Inference phase [CORE]

Classifies every operation by observed effect, builds effect footprints, assigns destructiveness tags, and scores field sensitivity. Runs per actor on planted objects, behind the gateway.

**Precondition: resettable target** (satisfied when the optional state-restoration trigger is configured, see P1 in section 2; otherwise the default pipeline in section 12 applies). Write inference needs the application state to be restorable to a known snapshot or seed (DB snapshot, seed/reset endpoint, disposable container). If the target is not resettable, the phase runs in **read-only mode**: GET classification and field scoring only; every write operation stays `unknown` and its verdicts go to `needs_review`.

#### [C2.1] GET-first ordering
GETs are assessed before any write, because their output is the readback used to assess everything else.

1. Execute each GET twice as the owner on planted objects. Compare normalized hashes ([C2.3]). Stable result: tag `read`. Changing result: the GET has a side effect; tag by observed effect (`mutate`, possibly `terminal`). This verifies the assumption "GET does not modify".
2. Build the **read index**: which GET returns which resource type, which fields, and which ID parameters it consumes.
3. For each POST/PUT/PATCH/DELETE, the **relation module** selects candidate related reads: shared path/query/body parameters, overlapping response schemas, same tenant/role scope. Hash-compare those reads before and after the write.
4. Classify the write: `create` (new entry appears), `mutate` (fields change), `advance` (a status-like field moves), `terminal` (object or lifecycle ends), `session_affecting` (credentials/actor change).
5. Store the **effect footprint** per operation: the set of reads and field paths that changed.

#### [C2.2] Footprint-based comparison
At probe time, diff only the footprint rather than the whole application. Run an occasional full comparison on a sample to detect incomplete footprints. Footprints are `inferred` and can miss side effects on unrelated objects; uncertain cases go to `needs_review`. State variables are the enum-like fields whose values change across observed writes, kept per entity (no global state).

#### [C2.3] Normalized and block hashing
- **Normalize before hashing:** sort object keys, normalize numbers and whitespace, sort arrays of objects by stable ID where order is not semantic, mask volatile values learned from the repeat reads (timestamps, request IDs, nonces, ETags, CSRF tokens).
- **Mask IDs consistently** with a per-run placeholder map (first appearance order) so equivalent states hash equal across resets and seeds.
- **Never mask** fields classified as ownership, tenant, or state (`owner_id`, `tenant_id`, `status`). Masking them would hide the very changes the oracle looks for.
- **Block (Merkle-style) hashes:** hash every leaf path and every subtree. Comparing the trees localizes which paths changed, so the footprint is a set of paths, not a yes/no.
- **Evidence:** keep the hashes, plus the redacted before/after values for the changed paths only.
- **Cautions:** over-normalization hides real changes; pagination and unstable ordering produce false diffs; hash equality means equality of the *normalized* form only. Pin the normalization version in the model version.

#### [C2.4] Destructiveness tags and configuration

| Tag | Meaning |
|---|---|
| `read` | no state change (verified by repeat reads) |
| `create` | adds entries |
| `mutate` | modifies fields, reversible |
| `advance` | moves a state forward (submit, approve, pay) |
| `terminal` | ends a lifecycle or destroys a privileged state; may be a GET, determined from observed effect, not method |
| `session_affecting` | changes credentials or the actor itself (password change, logout, role change) |
| `unknown` | not yet observed; treated as destructive |

**Ordering.** Within a flow, operations are sequenced by ascending destructiveness so the preferred state survives as long as possible and fewer objects are recreated. Principle 9 still applies: after any probe with observed effect, reset or re-plant.

**Destructiveness configuration** (enables/disables tests per tag):

```yaml
destructiveness:
  enabled_tags: [read, create, mutate, advance]
  disabled_tags: [terminal, session_affecting, unknown]
  per_operation_override: {}   # e.g. {delete_document: enabled}
```

Disabled operations are not used as attack probes and are reported as `skipped_by_config` (excluded from coverage denominators, listed separately). The gateway's approval gate reads the same tags.

#### [C2.5] Field exposure analysis (frontend-derived allowed set)
Goal: estimate, per actor and context, the **allowed field set** (the fields that actor's UI consumes or displays), then compare it with the fields the API returns (F3-R: returned set minus allowed set). Missing a leak is judged worse than raising a false candidate, so the analysis covers all captured routes and heuristics are not used to skip any.

**Signals, in priority order**

1. **Frontend-derived allowed set (primary).**
   - *Collection:* headless-browser replay per actor, with an init script that wraps parsed JSON responses and records which properties the page reads (field-access trace). Optional second layer: DOM text matching to learn which fields are actually *displayed*. Fallback when no live browser is available: static analysis of JS bundles taken from the HAR.
   - *Output per (actor/role, route, endpoint):* the consumed set, the displayed set where known, and a `bulk_access` flag when the code spreads, assigns, or stringifies a whole object (consumed, unknown whether shown).
   - *Timing:* a build-phase step, cached in the frozen model; it never runs at probe time.
2. **Direct heuristics (fast path and ranking).** Name and value patterns (`password`, hash, JWT, key, `*_internal`) flag a field immediately, with or without frontend evidence, and rank the candidate queue. They never decide which endpoints skip frontend analysis.
3. **Behavioral signals.** Write-only asymmetry (submitted but never returned to the same actor in any baseline response), OpenAPI `writeOnly`/`readOnly`, ownership-index leak (another actor's values in a response), and cross-actor field diff on the same object.
4. **Per-flow frequency (OPTIONAL).** Retained only as a feature for a Phase 2 ablation; it is not used in Phase 1 verdicts.

**Verdict rules**
- Returned field not in the actor's allowed set: F3-R candidate, prioritized by signals 2 and 3.
- Field consumed only through `bulk_access`: `needs_review`.
- Heuristic direct hit with no frontend evidence: candidate, high priority.
- The actor's own UI displays another user's object or field: evidence of intended visibility, which reduces implicit-allowance reviews.

**Cost of false positives.** Accepted by design (they are cheaper than false negatives), but they are triage burden, the quantity Phase 2 measures. Mitigations: ranking, the behavioral signals above, and reusable decisions (one ruling applies to the whole resource type). Report the candidate false-positive rate.

**Evidence:** the field-access trace, route and actor, returned set, allowed set, and heuristic hits.

**Limits:** reading a field is not displaying it; one session per actor is needed; coverage depends on which UI routes were exercised (lazy loading and dynamic content); producing the trace needs live app access (acceptable in an authorized environment). The trace travels inside the HAR as extension fields, so the input contract stays OpenAPI/HAR/inventory. A plain HAR without it falls back to static JS analysis plus signals 2 and 3.

**Discipline:** freeze heuristic lists and ranking weights on development apps before the held-out run; evaluate the analysis against the F3-R field policy in the ground truth.

#### [C2.6] HAR coverage and trust
HAR is untrusted (principle 8). Its inference-phase role: reveal hidden/optional request parameters and undeclared response fields that the OpenAPI document omits. These feed the mass-assignment candidates (6.2) and baseline field sets. Report **HAR coverage** (operations, parameters, and actors observed); tags and footprints for operations with thin coverage are marked low-confidence.

### [D] Model synthesis [CORE]
Builds the **Role-Session-Object (RSO)** model and the **observed state graph**, then freezes it.

**Ownership evidence tiers** (a `visible_to` relation is kept separate from `owned_by`):

| Tier | Evidence | Recorded as |
|---|---|---|
| Strong | Created by this actor's session; or owner field equals identity from `/me` or token claims | `owned_by` |
| Medium | Appears in an owner-scoped list (`/me/items`, `?owner=me`) | `owned_by` (medium) |
| Weak | Appears in a general list | `visible_to` only |

**Element status lifecycle:** `inferred` -> `probed` -> `human_confirmed` (or `rejected`).
Each element stores: source (input + request ID), tier/confidence, model version.

**State graph:** nodes = observed values of status-like fields; edges = observed transitions with actor, operation, preconditions seen. Negative edges are the complement of observed edges and are **hypotheses**, not truth (some are legitimate no-ops, so they route to `needs_review` when ambiguous).

**Freeze:** write `model_vN` (immutable). The oracle only reads the frozen snapshot. Any change creates `vN+1` with a recorded reason.

### [E] Calibration probes [CORE]
See section 5. Runs after the freeze and before attack probes, on reset state.

### [F] Probe generation [CORE]
Template mutations from the taxonomy; no free-form payloads.

| Family | Mutation template |
|---|---|
| F1 BOLA | owner creates object; same-tenant non-owner (and anonymous) repeats the same operation |
| F2 BFLA | low-privilege actor calls an operation observed only under a higher role |
| F3-R | read as each actor; diff returned fields against calibration/field policy and ownership index |
| F3-W | add one restricted/undeclared property per request (see section 6) |
| F4 | cross-tenant read/write/list |
| F5 | skip a step, repeat a single-use action, reverse a final state |

Every mutating probe runs on a freshly reset snapshot.

### [G] Gateway [CORE]
Host/path/method allowlist, action allowlist, request cap, rate/concurrency budget, dry-run, kill switch, audit log. Gateway allowlists control *forwarding*, never oracle expectations.

- **Direction rule.** Every *outbound* request (browser, crawler, or system-generated) is checked against scope. *Inbound* responses are passed, not scope-checked (size/time caps and redaction still apply). A redirect response is passed, but its next hop is a new outbound request and is checked again.
- **Blocked requests are recorded.** A blocked request is never forwarded; the caller gets an immediate gateway-marked response, and the event is stored with `gateway_verdict=blocked` and a reason. See `architecture.md`.
- **Undocumented paths (shadow-API handling).** An in-scope host with a path or method absent from the OpenAPI document is governed by an explicit config key `undocumented_policy` (`block`; `hold` = forward only if a pre-approved pattern matches, else block; `allow_and_flag`) that must be set before a run starts; a run with it unset refuses to start.

### [H] Oracle evaluation [CORE]
See section 7.

### [I] Evidence store [CORE]
One normalized event per request: run/workflow/sequence/step IDs, actor, operation, object refs, redacted request/response, status, body diff, before/after state (or hash), model version, seed, timestamp. Name each hash precisely (raw-body hash, canonical request fingerprint, response hash are different values).

### [J/K] Verdicts, report, HITL [CORE: queue; DEFERRED: effectiveness study]
Three outcomes: **violation**, **safe**, **needs_review**. Human decisions are stored as reusable per-endpoint/resource-type policies, so review happens once, not per finding.

---

## 5. Calibration probes (new baseline component) [CORE]

**Problem.** A deny is not always a 4xx, and a 2xx is not always a violation. Examples: BOLA returning 200 with an empty or filtered body is safe; BFLA returning 200 with no state change is safe; some apps return 200 with an error payload.

**Purpose.** Learn *how this app expresses allow and deny* before judging attack probes, so the oracle compares against observed signatures rather than assumed status codes.

**Calibration set (per operation family, per actor pair):**

| Probe | Expected | Learns |
|---|---|---|
| Owner performs the operation on own object | allowed | allow signature: status, body shape, field set, state effect |
| Anonymous performs it | denied | auth-deny signature |
| Nonexistent object ID as owner | not found | not-found signature |
| Malformed ID / schema-invalid body | rejected | validation-error signature (marks `valid_request=false`) |
| Known-denied pair if inventory/ground truth for the *lab* declares it | denied | policy-deny signature (benchmark runs only) |

**Signature fields:** status, error code/message pattern (sanitized), body keys, body-length band, headers of interest, and state-effect (changed / unchanged).

**Outputs**
- `deny_signatures[]`, `allow_signature`, `notfound_signature` per operation.
- A flag `distinguishable: true/false`. If deny and allow cannot be told apart by signature, that operation's results are `needs_review` unless state/leak evidence decides.
- A flag `status_unreliable: true` when the app returns 200 for errors.

**Evidence rules the oracle applies (replaces "2xx means fail")**

| Family | Violation requires | Not a violation |
|---|---|---|
| F1/F4 read | 2xx **and** response contains the target object's data (ownership-index match, or field values equal to the owner baseline) | 2xx with empty, generic, or filtered body |
| F1/F4 write/delete | 2xx **and** readback shows the object changed/deleted | 2xx with state unchanged |
| F2 | 2xx **and** state/effect changed (or privileged data returned) | 2xx with no state change |
| F3-R | returned fields outside actor's allowed set | allowed fields only |
| F3-W | restricted field value changed in readback | field ignored |
| F5 | state/side effects deviate from the graph or invariant | rejected, state unchanged |

**Consequences and cautions**
- Safety verdicts depend on a reliable readback. If no readback exists (no GET, no DB adapter), a 2xx on a mutating operation is `needs_review`, not safe.
- "State unchanged" must compare the *relevant* state (object fields, audit events), not only the response body. Side effects may be asynchronous: allow a bounded re-read.
- Record a 2xx-without-effect as `ineffective_attempt`. It is a hardening observation (the server accepted an unauthorized call), reported separately from violations.
- `families.yaml` already defines safe outcomes with effect conditions (F1 "no data of X", F2/F3-W/F5 "no state change"), and D3's "unless" clause allows per-app overrides. The only wording gap: safe responses are written as deny status plus no effect, so "2xx with no effect" is not explicitly safe. Add that clause. The older `docs/Taxonomy/README.md` oracle pseudocode (`Oracle_BFLA`, `Oracle_BOLA`) does flag on 2xx alone and should be aligned (see review item R1).

### 5.1 Readback strategy (no business-flow knowledge needed for F1-F4)

For authorization families, the question is "did something change that this actor must not change", not "was the transition correct". So the effect check can use the affected party's own session:

1. **Affected-party diff.** Before the probe, the owner (or victim tenant's actor) reads the target object via a legitimate GET; after the probe, reads it again. Any difference in non-volatile fields, or a 404 after DELETE, is effect evidence. This covers cross-tenant writes/deletes and same-tenant BOLA writes.
2. **Volatile-field calibration.** Run a no-op repeat read by the owner first and learn which fields change by themselves (`updated_at`, `read_count`, etc.). Exclude them from the diff.
3. **Planted objects make this reliable.** The owner and the object are known by construction, and the readback operation is the object's own GET, found via the dependency graph or HAR.
4. **Limits:**
   - Side effects on *other* objects (balances, audit events, counters) are missed by a single-object diff; add the related-object reads where the model knows them, else `needs_review`.
   - Operations with no target object (`system-reset`, export) have no object to diff; use response content and audit events, else `needs_review`.
   - F5 (is this transition valid?) is the one family that does need the state graph. A change by an *unauthorized* actor is a violation regardless of the graph, but judging a transition by an *authorized* actor needs it.

---

## 6. Mass assignment awareness [CORE]

### 6.1 What RESTler and Schemathesis cover
- **RESTler** infers producer-consumer dependencies and fuzzes bodies structurally; its checkers target crashes (5xx), use-after-free, resource hierarchy, namespace/leakage rules. The Godefroid et al. paper you attached states that extra response properties not in the schema are *ignored* in their implementation and lists mass-assignment checking as future work.
- **Schemathesis** generates schema-conformant and some schema-violating inputs and checks status codes, schema conformance, and similar. It has no ownership or privileged-field model.
- Neither models "this field must not be writable by this role".

(Verify against current RESTler/Schemathesis releases before citing in the report; this is from the attached paper and general knowledge, not a fresh source check.)

### 6.2 Candidate restricted-property discovery (static + HAR)
A property is a mass-assignment candidate if any holds:

1. Present in a **response** schema (or observed in HAR responses) but absent from the **request** schema of the write operation.
2. Marked `readOnly: true` in OpenAPI.
3. Observed in HAR responses but **undeclared** in any schema (the `is_admin`/`is_debug` case in the paper).
4. Request schema has `additionalProperties: true` or no `additionalProperties` restriction.
5. Name or value heuristics: `role`, `is_admin`, `owner_id`, `user_id`, `tenant_id`, `price`, `balance`, `status`, `verified`, `discount*`, `*_internal`.
6. Differs between actors: field present for admin responses, absent for user responses.

Each candidate stores its source and a priority score (rule-based; no ML).

### 6.3 Probe procedure
1. Reset to snapshot.
2. Valid baseline write as owner; record readback (`readback_before`).
3. Repeat with **one** candidate property added; record `readback_after`.
4. Compare: restricted property changed and equals injected value -> F3-W violation. Property ignored -> safe.
5. **Ownership/tenant fields** (`owner_id`, `tenant_id`) are first-class targets: a change in owner or tenant after a write is itself a finding.
6. Reset again. Never feed probe results back into the frozen RSO model.

### 6.4 Why this matters for the model
Ownership inferred from live traffic would be corrupted by a successful mass-assignment probe. The freeze + reset rules (section 1, principles 3) prevent this by construction.

---

## 7. Oracle and verdict logic [CORE]

```
Inputs: frozen model vN, calibration signatures, probe evidence (request, response,
        before/after state), ownership index
0. gateway_verdict is not "forwarded" (blocked, dry-run, tunneled, imported) -> record the event, no verdict, excluded from coverage and metrics
1. Is the request valid (schema, preconditions)? no -> record valid_request=false, no verdict
2. Match response against calibration signatures:
   - matches deny signature            -> safe
   - matches allow/notfound unclear    -> continue
3. Apply family evidence rule (section 5 table):
   - effect evidence present           -> violation
   - effect evidence absent, readback reliable -> safe (log ineffective_attempt if 2xx)
   - readback unavailable or signatures indistinguishable -> needs_review
4. Implicit-allowance check (see 8) before final violation for reads
```

**Gateway verdicts are not target verdicts.** A gateway block (even if it returns 403 to the caller) must never be read as the application denying access (D3). The oracle reads only events the target actually answered, identified by the `gateway_verdict` field and the gateway-block marker header. A misconfigured allowlist would otherwise show up as "everything is safe".

---

## 8. Cases routed to `needs_review` [CORE]

| Situation | Reason | Reduction heuristic |
|---|---|---|
| Implicit allowance (public-by-design objects, e.g. repo listings) | Policy intent is human knowledge | Was the object reachable through the actor's *own* legitimate traffic? Is it in a public list? Does the operation have no security requirement? Can anonymous read it? Judge per method (read allowed, write denied is common) |
| Excessive data exposure | "Sensitive" is not decidable from traffic | Compare returned fields with the frontend-derived allowed set ([C2.5]); heuristics for direct hits and ranking; ownership-index leak, cross-actor field diff, undeclared/`writeOnly` fields |
| Ambiguous negative edges | Complement of observed edges includes legitimate no-ops | Probe, then review only those that succeed |
| No readback / indistinguishable signatures | Cannot establish effect | Add a state adapter or a HAR-derived readback operation |
| Unknown policy | Missing rule is not deny | Present evidence; store decision as reusable policy |

---

## 9. Evaluation (benchmark only)

- Ground truth (planted + benign cases, `development` vs `held-out`) is joined **after** execution by the evaluator; the tool never reads it.
- Metrics: workflow, operation, role/object-pair coverage; valid-sequence rate; provenance rate; planted-case coverage; precision/recall/FPR per family; planting coverage; calibration quality (share of operations with a distinguishable deny signature).
- Events with `gateway_verdict` other than `forwarded` are excluded from coverage, valid-sequence, and detection metrics, and reported separately (blocked, tunneled, and imported counts). The safety KPI counts requests that *reached the upstream* outside the allowlist; blocked attempts are not violations.
- Also compare the *inferred* model against the ground-truth model (edge/ownership precision and recall). This measures RQ1.
- Freeze metrics, split, and model before the measurement run.

---

## 10. Module scoping summary

| Module | Tag |
|---|---|
| OpenAPI/HAR ingest, normalization, redaction | CORE |
| Environment inventory (minimal) | CORE |
| Dependency graph and field classification | CORE |
| HAR-template seed planting | CORE |
| Producer-consumer planting | CORE (basic) |
| Inference phase (GET-first, footprints, normalized/block hashing) | CORE |
| Destructiveness tags and configuration | CORE |
| Field exposure analysis (allowed set + heuristics + behavioral signals) | CORE |
| Per-flow frequency scoring | OPTIONAL (Phase 2 ablation) |
| Flow enumeration | CORE |
| Model synthesis, evidence tiers, freeze | CORE |
| Calibration probes | CORE |
| Template-based probe generation (F1-F5) | CORE |
| Mass-assignment candidate discovery and probes | CORE |
| Safety Gateway, evidence store | CORE |
| `needs_review` queue | CORE |
| Crawler as HAR capture assistant | OPTIONAL |
| Frontend replay and field-access tracing | CORE (static JS analysis as fallback) |
| DB read adapter | OPTIONAL |
| AI planner/ranker, LLM, ML ranking | DEFERRED |
| HITL effectiveness study | DEFERRED |

---

## 11. Audit checklist and open questions

**Review items (for you to audit)**

- R1. In `families.yaml`, add an explicit clause that a 2xx with no leak/no state change is also a safe outcome. Align the `docs/Taxonomy/README.md` oracle pseudocode (`Oracle_BOLA`, `Oracle_BFLA`), which still flags on 2xx alone, with the effect-based rules in section 5.
- R2. The existing `oracle_types` use `requires: [access_policy]`. In the final system the policy is inferred; decide what the oracle reads when no confirmed policy exists (proposal: calibration signatures + captured reference actor, status `inferred`).
- R3. Confirm the lab ground truth and the tool are never co-located in inputs (leakage check).
- R4. Define `valid_request` for tool-generated probes the same way the harness does.
- R5. Hash naming in the evidence schema (`raw_hash` is ambiguous). Add a distinct name for normalized and block hashes ([C2.3]) and pin the normalization version.
- R6. Check the ID-masking whitelist: ownership, tenant, and state fields must never be masked.
- R7. Define "flow" precisely (root-to-terminal enumeration, deduplication, cap on path count), since flows still drive operation ordering.
- R10. Validate the field-access trace on `bulk_access` patterns (spread, `Object.assign`, `JSON.stringify`) and decide how they are reported.
- R12. Add `gateway_verdict` and the block-marker header to the evidence schema; check that the oracle and the coverage script both filter on it.
- R13. Confirm no client in the system (RunTrace, replay harness, Playwright) follows redirects by itself; every hop must re-enter the gateway.
- R11. Define the HAR extension fields (`_actor`, `_fieldAccess`) and the fallback behavior for a plain HAR. The crawl itself is a capture assistant, not a separate input.
- R8. Decide the semantics of `disabled_tags`: may `unknown` operations be executed once on a disposable snapshot purely to classify them, or never?
- R9. The `terminal` tag can apply to a GET; confirm the probe phase is where that is detected and that the tag then overrides the method-based default.

**Open questions**

- Q1. Source of actor identity (inventory vs per-actor HAR).
- Q2. Is a readback operation always available? If not, which targets fall back to the DB adapter?
- Q3. Minimum calibration set per operation: is one owner/anonymous/nonexistent triple enough?
- Q4. How are credentials obtained for planting (login flow in HAR, or supplied)?
- Q5. Is `ineffective_attempt` reported as a finding class or only logged?
- Q6. Crawler: keep as HAR capture assistant, or drop for Phase 1?

**Resolved by team decision**

- Flows are enumerated for every root-to-terminal path ([B]).
- GET operations are assessed and classified first ([C2.1]).
- Every HAR is treated as untrusted; its role is revealing hidden/optional parameters and undeclared response fields ([C2.6]).
- State comparison stays in the pipeline, using normalized and block hashes ([C2.3]).
- A destructiveness configuration enables or disables tests per tag ([C2.4]).
- Per-flow frequency is demoted to an optional Phase 2 feature. The frontend-derived allowed set is the primary exposure signal; heuristics handle direct hits and ranking ([C2.5]).

**New open questions**

- Q7. Is the target resettable (snapshot, seed/reset endpoint, disposable container)? If not, only read-only mode applies ([C2]).
- Q8. How are the heuristic lists and ranking weights chosen without tuning on the held-out apps?
- Q9. What minimum HAR coverage makes a tag or footprint trustworthy rather than low-confidence?
- Q11 (resolved). Held requests are approved by pre-configured patterns only; unmatched requests are blocked. Interactive approval is deferred (see `architecture.md` DR10).
- Q12 (pending supervisor). Is an opaque per-app state-restoration trigger acceptable as part of the environment inventory/configuration? See P1 in section 2.
- Q10. Does the relation module (shared params, schema overlap, tenant/role scope) get a confidence score, so weak relations are verified with a full comparison?

---

## 12. Discussed but not yet applied

Design points agreed in discussion but not yet written into the sections above. They form the default pipeline used when no state-restoration trigger is configured (P1); with a trigger, some of them simplify.

- Reset precondition becomes three tiers: (1) resettable, (2) plantable and cleanable (fresh-object isolation, tool-created data tagged for cleanup), (3) neither (passive capture and read-only classification).
- Re-baseline pass after inference and before the model freeze; dirty tracking of objects touched by probes with observed effect; footprints keyed by (operation, object state).
- Every test sequence is self-contained (plant, probe, read back) so replay does not depend on leftover state; planting requests count toward budgets and requests per valid finding.
- `auth` operation class (register, login, logout, token refresh, password reset); flows start at the first non-`auth` node with an implicit actor-session precondition; auth events do not count as test steps or workflow coverage.
- Actor liveness check before tests (session valid, identity matches the frozen model, not locked); a failure produces `actor_unavailable`, never a verdict; no wrong-credential probing of login endpoints (D2).
- `identity_risk` probe class (probes that touch role, tenant, owner or permission fields) in addition to the operation-level `session_affecting` tag; post-probe identity check; taint tracking in run state; `identity_risk_mode: twin | last_with_taint | disabled`; an identity change after a probe is itself a finding.
- Benchmark runs still reset every configuration to the same initial state for fair comparison.
- With a state-restoration trigger (P1), the per-test flow is: restore, plant fresh objects, probe, read back; restoration success is verified through the API, and restored accounts are re-checked for liveness.