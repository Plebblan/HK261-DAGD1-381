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

---

## 2. Inputs

| Input | Format | Provides | Does not provide | Tag |
|---|---|---|---|---|
| OpenAPI document | JSON/YAML | Operations, schemas, params, security schemes/scopes, declared success and error responses, examples, `readOnly`/`writeOnly`, `additionalProperties` | Roles, ownership, business rules, forbidden transitions | CORE |
| HAR traffic | `.har` files, or passive proxy capture during manual interaction | Valid real sequences, ID flow between requests, per-session identity, observed status/field changes, hidden preconditions satisfied in practice | Anything the operator did not exercise | CORE |
| Environment inventory | *Proposed redefinition* (see below) | Actors, in-scope hosts, optional declared seed objects | Policy, state rules | CORE (minimal) |
| Frontend/crawler capture | Emitted as HAR | Extra valid sequences per actor UI | Authorization truth | OPTIONAL |
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

---

## 3. Pipeline overview

```
 OpenAPI ─┐
 HAR ─────┼─> [A] Ingest & normalize
 Inventory┘            │
                       v
              [B] Static model (operations, dependency graph, field classification)
                       │
                       v
              [C] Seed planting & workflow capture   (uses [B] + HAR templates)
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
2. **Field classification** per resource schema (see section 6): user-writable, server-controlled, sensitive, ownership-bearing.
3. **Declared-behavior hints**: security requirements per operation, declared 401/403/404 responses. Treat as weak priors only.

### [C] Seed planting & workflow capture [CORE: HAR templates; OPTIONAL: expansion]
Goal: obtain objects with *known owner and tenant*, and valid workflow orderings.

1. **HAR templates (core).** Captured valid sequences are replayed per actor to create objects. These already satisfy hidden preconditions.
2. **Producer-consumer planting (core).** For creatable resources not covered by a template, build a chain from [B], fill bodies from schema examples, enums, and values learned from earlier responses.
3. **Runtime-feedback expansion (optional).** Try uncovered operations against planted objects and classify the response:
   - success: record a transition observation
   - 400/409: unmet precondition; queue after another operation
   - 401/403/404: possible access boundary; record only
4. **Coverage report (core).** Operations that could not be planted are marked `unplanted`. Do not guess.
5. **DB ingestion (optional).** Only for non-creatable objects, read-only.

Known limits: data-/time-dependent rules, cross-actor handoffs without an actor with the right role, admin-provisioned data.

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

---

## 8. Cases routed to `needs_review` [CORE]

| Situation | Reason | Reduction heuristic |
|---|---|---|
| Implicit allowance (public-by-design objects, e.g. repo listings) | Policy intent is human knowledge | Was the object reachable through the actor's *own* legitimate traffic? Is it in a public list? Does the operation have no security requirement? Can anonymous read it? Judge per method (read allowed, write denied is common) |
| Excessive data exposure | "Sensitive" is not decidable from traffic | Use ownership-index leak, cross-actor field diff, undeclared/`writeOnly` fields, sensitivity heuristics; frontend-render parsing is an *optional* priority signal only |
| Ambiguous negative edges | Complement of observed edges includes legitimate no-ops | Probe, then review only those that succeed |
| No readback / indistinguishable signatures | Cannot establish effect | Add a state adapter or a HAR-derived readback operation |
| Unknown policy | Missing rule is not deny | Present evidence; store decision as reusable policy |

---

## 9. Evaluation (benchmark only)

- Ground truth (planted + benign cases, `development` vs `held-out`) is joined **after** execution by the evaluator; the tool never reads it.
- Metrics: workflow, operation, role/object-pair coverage; valid-sequence rate; provenance rate; planted-case coverage; precision/recall/FPR per family; planting coverage; calibration quality (share of operations with a distinguishable deny signature).
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
| Runtime-feedback expansion | OPTIONAL |
| Model synthesis, evidence tiers, freeze | CORE |
| Calibration probes | CORE |
| Template-based probe generation (F1-F5) | CORE |
| Mass-assignment candidate discovery and probes | CORE |
| Safety Gateway, evidence store | CORE |
| `needs_review` queue | CORE |
| Crawler as HAR capture assistant | OPTIONAL |
| Frontend-render parser | OPTIONAL |
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
- R5. Hash naming in the evidence schema (`raw_hash` is ambiguous).

**Open questions**

- Q1. Source of actor identity (inventory vs per-actor HAR).
- Q2. Is a readback operation always available? If not, which targets fall back to the DB adapter?
- Q3. Minimum calibration set per operation: is one owner/anonymous/nonexistent triple enough?
- Q4. How are credentials obtained for planting (login flow in HAR, or supplied)?
- Q5. Is `ineffective_attempt` reported as a finding class or only logged?
- Q6. Crawler: keep as HAR capture assistant, or drop for Phase 1?