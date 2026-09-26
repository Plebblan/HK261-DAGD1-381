# Research Question Analysis and Phase 1 Development Scope

## 1. RQ1 — Role–Session–Object and Business State Modeling

### Research Question

> **RQ1: How can Role–Session–Object topologies and Business State Graphs be automatically synthesized from OpenAPI specifications and passive traffic captures?**

### Analysis

RQ1 addresses the problem of representing the **semantic context** required for stateful authorization and business-logic testing.

Traditional schema-based API testing can identify endpoints, parameters, and basic request dependencies from OpenAPI specifications. However, authorization and business-logic vulnerabilities often depend on relationships that are not explicitly represented in the API schema, such as:

* Which user belongs to which role.
* Which session belongs to which actor.
* Which tenant owns an object.
* Which user is the owner of an object.
* Which actor is allowed to perform an action.
* Which business state an object is currently in.
* Which state transitions are valid.
* Which actions require a particular precondition.

Therefore, RQ1 is essentially concerned with constructing a structured representation:

```text
Role
   ↓
Session / Actor
   ↓
Action
   ↓
Object / Resource
   ↓
Business State
   ↓
State Transition
```

For example:

```text
User A
  └── Role: Customer
       └── Session A
            └── owns Order #101
                  └── CREATED
                       ↓
                     PAY
                       ↓
                     PAID
```

This representation is important because later testing needs to determine whether another actor can incorrectly access or modify the same object, or whether an action can be performed when the object is in an invalid state.

### What Phase 1 Should Implement

Phase 1 should implement a **machine-readable Role–Session–Object and State representation**.

The system should be able to represent at least:

```text
Actor
Role
User
Tenant
Session
Token / Scope
Object
Object Owner
Relationship
Endpoint
HTTP Method
Action
Precondition
Postcondition
Business State
State Transition
```

Input sources can include:

```text
OpenAPI
HAR
Proxy Traffic
Manual Workflow
```

The output should be reviewable and serializable, for example:

```yaml
actor:
  id: user_01
  role: customer
  tenant: tenant_A

session:
  id: session_01
  actor: user_01

object:
  type: order
  id: order_101
  owner: user_01
  tenant: tenant_A

action:
  endpoint: /orders/{id}
  method: GET

state:
  before: CREATED
  after: CREATED
```

### Phase 1 Limitation

Phase 1 should **not require fully autonomous semantic understanding** of arbitrary Web/API applications.

The objective is to demonstrate that the model can be:

1. Constructed from available API/traffic information.
2. Reviewed and corrected by a human.
3. Serialized into a machine-readable format.
4. Used by the replay and testing infrastructure.

Therefore, the appropriate scope is **semi-automated modeling with human validation**, rather than claiming complete automatic synthesis.

---

# 2. RQ2 — AI-Assisted Test Sequence Planning

### Research Question

> **RQ2: How can an AI-assisted Planner/Ranker be formulated with formal constraints to prioritize request sequences that maximize flaw discovery probability under strict testing budgets?**

### Analysis

RQ2 addresses the **state-space explosion problem**.

Once multiple:

* actors,
* roles,
* sessions,
* objects,
* tenants,
* states,
* actions,

are combined, the number of possible request sequences can become very large.

For example:

```text
Login
 → Create Object
 → Update Object
 → Switch Actor
 → Read Object
 → Update Object
 → Change State
 → Switch Tenant
 → Read Object
 → ...
```

Testing every possible sequence is inefficient.

Therefore, RQ2 investigates whether an AI-assisted planner/ranker can identify sequences that are more valuable for testing authorization and business-logic properties.

The planner would eventually receive information such as:

```text
OpenAPI
+
Role–Session–Object Model
+
Business State Graph
+
Finding History
+
Triage Feedback
```

and produce:

```text
Target Sequence
Preconditions
Expected Evidence
Budget
Reason for Selection
```

### What Phase 1 Should Implement

Phase 1 should **not implement the AI Planner/Ranker itself**.

Instead, Phase 1 should build the infrastructure required by RQ2:

* Stateful workflow representation.
* Replayable request sequences.
* State reset.
* Request budget measurement.
* Sequence execution logs.
* Coverage measurement.
* Ground-truth vulnerability scenarios.
* Baseline strategies.

Phase 1 should provide deterministic baselines such as:

```text
Manual / Burp Checklist
        ↓
Role-Matrix Regression
        ↓
Random / State-Unaware Mutation
        ↓
Schema-Based Negative Testing
```

These baselines provide the comparison point for the AI planner in Phase 2.

### Phase 1 Limitation

The following are outside the Phase 1 implementation:

* LLM-based sequence generation.
* AI ranking.
* Prompt optimization.
* AI feedback loops.
* Autonomous test planning.
* Comparison between AI and existing approaches.

These activities belong to Phase 2, where the project explicitly introduces the AI-assisted Planner/Ranker.

Thus, the Phase 1 contribution to RQ2 is **preparing the experimental infrastructure**, rather than answering RQ2 completely.

---

# 3. RQ3 — Authorization and State Verification Oracles

### Research Question

> **RQ3: How should Differential Authorization and State Invariant Oracles be designed to reliably detect authorization breaches without excessive false positives?**

### Analysis

RQ3 addresses the problem of determining whether an executed sequence actually represents a security violation.

A simple HTTP-status check is insufficient.

For example:

```text
User A owns Object #100

User B requests:
GET /objects/100

Response:
200 OK
```

The system cannot simply conclude:

```text
200 = Vulnerability
```

Instead, it needs contextual information:

```text
Actor: User B
Role: Customer
Tenant: Tenant B
Object Owner: User A
Expected Access: DENY
Observed Access: ALLOW
```

The oracle therefore needs to compare **expected behavior against observed behavior**.

For authorization:

```text
Expected Authorization
        vs.
Observed Authorization
```

For business logic:

```text
Expected State Transition
        vs.
Observed State Transition
```

Example:

```text
Expected:

CREATED
  ↓
PAY
  ↓
PAID

Observed:

CANCELLED
  ↓
PAY
  ↓
PAID
```

The second transition may indicate a workflow/business-logic violation.

### What Phase 1 Should Implement

Phase 1 should establish **deterministic baseline oracles**.

These can include:

#### Authorization Oracle

```text
Role Matrix
+
Object Ownership
+
Tenant Relationship
+
Expected Access
+
Observed Access
```

#### State Oracle

```text
Current State
+
Requested Action
+
Expected Transition
+
Observed Transition
```

#### Evidence

Each candidate finding should contain:

```text
Request
Response
Actor
Object
State Before
State After
Expected Result
Observed Result
Difference
Replay Information
```

This creates a ground-truth mechanism for Phase 2.

### Phase 1 Limitation

Phase 1 should not attempt to develop highly general semantic reasoning for arbitrary applications.

The oracle should be restricted to:

* predefined vulnerability families;
* known roles;
* known ownership relationships;
* known tenant relationships;
* explicitly modeled states;
* predefined state invariants;
* controlled Cyber Range scenarios.

The more advanced automated oracle mechanisms can then be investigated in Phase 2.

---

# 4. RQ4 — Human-in-the-Loop Triage

### Research Question

> **RQ4: What is the quantitative impact of a Human-in-the-loop (HITL) triage framework on improving detection precision and reducing verification overhead?**

### Analysis

RQ4 addresses the final stage of the testing pipeline.

Even if an automated system produces suspicious findings, not every candidate necessarily represents a valid vulnerability.

The workflow is therefore:

```text
Test Sequence
      ↓
Candidate Finding
      ↓
Evidence
      ↓
Human Review
      ↓
Valid / Invalid
      ↓
Final Finding
```

HITL triage is particularly important because authorization and business-logic testing often depends on application-specific semantics.

The human analyst can verify:

* Whether the authorization violation is real.
* Whether the object actually belongs to another actor.
* Whether the state transition violates the intended workflow.
* Whether the evidence is sufficient.
* Whether the finding is reproducible.
* Whether the finding should be classified as BOLA, BFLA, BOPLA, tenant isolation, or workflow abuse.

The final research objective is then to measure whether HITL improves:

```text
Precision
Triage Time
False Positive Rate
Verification Cost
```

### What Phase 1 Should Implement

Phase 1 should only prepare the **inputs required for future HITL evaluation**:

* Standardized evidence records.
* Replayable test cases.
* Ground-truth labels.
* Finding classification.
* Manual verification procedure.
* Baseline triage measurements.

A simple manual process can be established:

```text
Candidate
   ↓
Replay
   ↓
Compare Expected / Observed
   ↓
Analyst Decision
   ↓
Ground-Truth Label
```

### Phase 1 Limitation

Phase 1 should not claim to evaluate the effectiveness of HITL quantitatively.

In particular, Phase 1 does not need to prove:

```text
Precision ≥ 0.85
```

or:

```text
Triage time reduced ≥ 25%
```

Those are Phase 2 evaluation targets. The existing specification explicitly assigns the precision and triage-efficiency evaluation to Phase 2.

---

# 5. Overall Phase 1 Development Boundary

Based on the four RQs, the boundary of Phase 1 can be summarized as follows:

| Research Question  | Phase 1 Contribution                                               | Phase 1 Boundary                                                                 |
| ------------------ | ------------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| **RQ1 — Modeling** | Build Role–Session–Object and Business State models                | Semi-automated + human validation; no requirement for full autonomous inference  |
| **RQ2 — Planning** | Build replay, state, budget, coverage, and baseline infrastructure | No AI Planner/Ranker or autonomous LLM testing                                   |
| **RQ3 — Oracle**   | Build deterministic authorization/state verification baselines     | Limited to modeled roles, objects, states, and predefined vulnerability families |
| **RQ4 — HITL**     | Prepare evidence, ground truth, and manual verification workflow   | No quantitative HITL effectiveness study in Phase 1                              |

Therefore:

```text
                    PHASE 1
                       │
        ┌──────────────┼──────────────┐
        ↓              ↓              ↓
      RQ1            RQ2            RQ3
    Modeling      Infrastructure     Baseline
        │              │              │
        └──────────────┼──────────────┘
                       ↓
              Reproducible Foundation
                       │
                       ↓
                    PHASE 2
                       │
                 ┌─────┴─────┐
                 ↓           ↓
               RQ2          RQ4
             AI Planner     HITL
                 │
                 ↓
          Advanced Oracle
                 │
                 ↓
          Final Evaluation
```

## Final Phase 1 Boundary

The **core boundary** should therefore be:

> **Phase 1 develops a reproducible, stateful Web/API security-testing foundation consisting of Role–Session–Object modeling, Business State representation, workflow capture and replay, deterministic authorization/state verification, evidence collection, Cyber Range infrastructure, and experimental baselines. It does not implement AI-based test planning, autonomous LLM testing, advanced AI-driven oracle generation, or quantitative HITL evaluation.**

This keeps the Phase 1 scope aligned with the existing 15-week plan: Cyber Range, state modeling, workflow/replay, evidence, safety, and baselines are the deliverables, while AI planning and HITL evaluation remain the main research work of Phase 2.
