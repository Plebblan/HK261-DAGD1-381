# Authorization and Business-Logic Vulnerability Taxonomy for Stateful Web/API Security Testing

The modern cloud API ecosystem relies heavily on complex multi-tenant architectures, diverse user roles, dynamic session tokens, and multi-step stateful workflows. As established in API security research and industry standards, authorization flaws rarely manifest as static syntax errors. Instead, they expose themselves when comparing the behavioral outcomes of different actors attempting actions on shared objects or within specific business logic states. This document establishes a formal vulnerability taxonomy for stateful web and API security testing, focusing on the four primary authorization and business logic risk categories identified in the OWASP API Security Top 10 (2023).

---

## 1. Architectural & Testing System Context

To systematically detect permission and state manipulation vulnerabilities without inducing high rates of false positives or unconstrained fuzzing explosions, automated security testing must operate against a structured model of application behavior. As demonstrated in stateful API testing frameworks like RESTler, effective vulnerability discovery requires tracking producer-consumer dependencies across HTTP request sequences—for instance, ensuring that a resource identifier produced by a creation request is correctly passed to subsequent read, update, or deletion operations.

In multi-tenant API testing systems, this sequence generation is extended to incorporate actor switching and state tracking. Testing is executed within a containerized Cyber Range environment containing synthetic multi-tenant applications, seeded user accounts, and fixed database snapshot reset mechanisms. The taxonomy defined herein provides the objective decision rules (oracles), precondition structures, evidence schemas, and expected safe responses required by automated test planners and human triage analysts to verify true security violations.

### System Pipeline & Data Flow

1. **Specification & Traffic Ingestion**: Ingests OpenAPI/Swagger specifications and passive HAR traffic logs to discover endpoints, request bodies, and route parameters.
2. **Topology Synthesis**: Synthesizes the Role-Session-Object (RSO) topology and business state graph, mapping actor permissions, object ownerships, and allowed state transitions.
3. **Stateful Sequence Generation**: Generates targeted HTTP request sequences featuring cross-actor object substitutions and multi-step workflow execution.
4. **Oracle Evaluation & Triage**: Evaluates execution traces through automated Differential Authorization and State Invariant Oracles, formatting verified violations into normalized evidence schemas for human-in-the-loop (HITL) triage.

---

## 2. Role-Session-Object Topology & State Foundations

Automated authorization testing relies on a formal Actor-Resource-Action-State model, encoded in structured YAML or JSON schemas. This model governs how test sequences switch contexts and evaluate authorization rules.

### Core Topology Components

* **Actors & Roles ($A$, $R$)**: Formally represents user accounts ($u \in U$), assigned functional roles ($r \in R$), and organizational tenant boundaries ($t \in T$). A test context specifies the active session token and scope associated with a specific actor $A_i = (u_i, r_i, t_i)$.
* **Resources & Objects ($O$)**: Represents dynamic domain entities (such as orders, documents, tickets, or user profiles) created or manipulated via API endpoints. Each object $o_k \in O$ maintains an explicit ownership association $o_k.owner \in U$ and tenant association $o_k.tenant \in T$.
* **Actions & Methods ($Act$, $M$)**: Represents HTTP operations (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`) exposed at specific endpoint routes.
* **Business States ($S$)**: Represents the lifecycle phase of a resource or workflow (such as `Draft` $\rightarrow$ `Submitted` $\rightarrow$ `Approved` $\rightarrow$ `Fulfilled`). Transitions between states require satisfying strict preconditions and postconditions.

### Contextual Interaction Workflow

* **Step 1 (Context Definition)**: Define the requesting actor context $A_i$ with an active authentication session token.
* **Step 2 (Target Selection)**: Select an operation (HTTP Method + Endpoint) targeting object instance $o_k$.
* **Step 3 (Precondition Check)**: Verify that required dynamic object identifiers ($CONSUMES$) are satisfied by prior responses in the active sequence ($PRODUCES$).
* **Step 4 (Execution & Differential Analysis)**: Execute the HTTP request and pass the resulting status, body diff, and database state to the corresponding verification oracle.

---

## 3. Core Vulnerability Taxonomy

### 3.1 Broken Object Level Authorization (BOLA / IDOR)

* **Industry Standards Mapping**: OWASP API1:2023 | CWE-284 (Improper Access Control), CWE-639 (Insecure Direct Object Reference)
* **Description & Threat Mechanism**: BOLA occurs when an API endpoint exposes dynamic resource identifiers in request paths, query parameters, or payload bodies without validating that the requesting actor holds explicit authorization to access or modify that specific object instance. In multi-tenant environments, BOLA manifests in two forms: horizontal privilege escalation (User A accessing User B's object within the same tenant) and tenant isolation breakage (User A in Tenant 1 accessing an object belonging to Tenant 2).

#### Operational Criteria & Preconditions
* **Precondition 1 (Object Creation)**: Actor $A_1 = (u_1, r_{user}, t_1)$ executes a producer request (e.g., `POST /api/v1/documents`) to create object $o_1$. The response parser captures $o_1.id$.
* **Precondition 2 (Cross-Actor Substitution)**: Actor $A_2 = (u_2, r_{user}, t_1)$ where $u_2 \neq u_1$, or Actor $A_3 = (u_3, r_{user}, t_2)$ where $t_2 \neq t_1$, issues a consumer request (e.g., `GET /api/v1/documents/{o_1.id}` or `DELETE /api/v1/documents/{o_1.id}`) substituting $o_1.id$ while presenting $A_2$'s or $A_3$'s active authentication token.

#### Sequence Substitution Workflow
1. **Producer Request**: Actor $A_1$ (Tenant 1) sends `POST /api/v1/documents` $\rightarrow$ Server creates `object_id = 101`.
2. **Actor Context Switch**: Test runner switches active session header to Actor $A_2$ (Tenant 2).
3. **Consumer Request**: Actor $A_2$ sends `GET /api/v1/documents/101` $\rightarrow$ Target endpoint processes request under $A_2$'s context.

#### Expected Safe Response vs. Vulnerable Behavior
* **Expected Safe Response**: HTTP `403 Forbidden` or `404 Not Found` (to prevent object existence enumeration), accompanied by an unmodified database state.
* **Vulnerable Behavior**: HTTP `200 OK` or `204 No Content` returning object $o_1$'s data or confirming state mutation/deletion by an unauthorized actor.

#### Evidence Requirements
* Recorded HTTP request/response exchange for object creation by Actor $A_1$.
* Recorded HTTP request/response exchange for unauthorized access attempt by Actor $A_2$ or $A_3$.
* Normalized JSON evidence diff confirming object state retrieval or unauthorized database mutation.

#### Automated Verification Oracle
```
Oracle_BOLA(Response, StateBefore, StateAfter):
  IF Request.Actor != Object.Owner AND Request.Actor.Tenant != Object.Tenant:
    IF Response.StatusCode IN [200, 201, 202, 204] OR StateAfter != StateBefore:
      RETURN FAIL("BOLA Violation Detected: Unauthorized Object Access/Mutation")
  RETURN PASS
```

---

### 3.2 Broken Object Property Level Authorization (BOPLA)

* **Industry Standards Mapping**: OWASP API3:2023 | CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies), CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes / Mass Assignment)
* **Description & Threat Mechanism**: BOPLA combines the concepts previously classified as Excessive Data Exposure and Mass Assignment. It addresses vulnerabilities where an API endpoint fails to validate authorization at the granular property/field level of an object. This allows unauthorized actors to either read sensitive internal fields (Property Ingestion/Exposure) or manipulate restricted object properties (Mass Assignment/Property Tampering)—such as modifying `is_admin`, `price`, `account_balance`, or `tenant_id` during standard updates.

#### Operational Criteria & Preconditions
* **Precondition 1 (Schema & Property Inspection)**: OpenAPI schema defines readable or writable object properties, distinguishing between standard user-editable properties ($P_{user}$) and restricted administrative/system properties ($P_{restricted}$).
* **Precondition 2 (Property Tampering Request)**: Actor $A_1 = (u_1, r_{user}, t_1)$ submits a creation or update request (`POST`, `PUT`, `PATCH`) incorporating $P_{restricted}$ within the JSON payload body (e.g., `{"profile_name": "New", "role": "admin", "discount_rate": 100}`).
* **Precondition 3 (Excessive Exposure Request)**: Actor $A_1$ queries an endpoint that returns the full object graph, including sensitive fields reserved for internal or elevated roles (e.g., password hashes, internal API keys, internal status flags).

#### Mass Assignment Injection Workflow
1. **User Request**: Standard User sends `PATCH /api/v1/users/me` with JSON body `{"name": "Alice", "is_admin": true}`.
2. **Server Processing**: Server updates user record without filtering restricted property `is_admin`.
3. **Property Verification**: Database state inspection verifies `is_admin` changed from `false` to `true`.

#### Expected Safe Response vs. Vulnerable Behavior
* **Expected Safe Response**: HTTP `400 Bad Request` or `422 Unprocessable Entity` rejecting unauthorized properties, or HTTP `200 OK` with the server strictly ignoring $P_{restricted}$ mutations. For read operations, sensitive properties are filtered out based on the requester's token scope.
* **Vulnerable Behavior**: HTTP `200 OK` or `201 Created` where database state reflects successful modification of $P_{restricted}$, or response body exposes unmasked sensitive properties to unauthorized roles.

#### Evidence Requirements
* Full API payload schema marking $P_{user}$ versus $P_{restricted}$.
* Raw HTTP request featuring injected restricted properties.
* Pre-action and post-action database state snapshots demonstrating unauthorized property modification.

#### Automated Verification Oracle
```
Oracle_BOPLA(Response, StateBefore, StateAfter):
  FOR EACH property p IN Request.Payload:
    IF p IN RestrictedProperties AND Request.Actor.Role NOT IN AuthorizedRoles(p):
      IF StateAfter[p] != StateBefore[p] AND StateAfter[p] == Request.Payload[p]:
        RETURN FAIL("BOPLA Mass Assignment Violation: Restricted Property Modified")
  FOR EACH property p IN Response.Body:
    IF p IN SensitiveProperties AND Request.Actor.Role NOT IN AuthorizedRoles(p):
      RETURN FAIL("BOPLA Excessive Data Exposure: Sensitive Property Exposed")
  RETURN PASS
```

---

### 3.3 Broken Function Level Authorization (BFLA)

* **Industry Standards Mapping**: OWASP API5:2023 | CWE-285 (Improper Authorization)
* **Description & Threat Mechanism**: BFLA occurs when an API fails to enforce proper function-level access control checks, allowing lower-privileged users or unauthenticated actors to execute restricted administrative or elevated operations. APIs often exhibit complex hierarchy structures where administrative paths (`/api/v1/admin/users`) or sensitive HTTP methods (`DELETE`, `PUT`) are left unprotected under the assumption that clients will hide administrative UI controls.

#### Operational Criteria & Preconditions
* **Precondition 1 (Role Hierarchy Mapping)**: The API topology defines an elevated role $R_{admin}$ authorized for function $F$ (e.g., `POST /api/v1/admin/system-reset` or `DELETE /api/v1/users/{id}`) and a standard role $R_{user}$ explicitly restricted from function $F$.
* **Precondition 2 (Cross-Role Function Invocation)**: Actor $A_{user} = (u_1, r_{user}, t_1)$ transmits an HTTP request directly targeting administrative endpoint function $F$ using $A_{user}$'s valid session token.

#### Function Privilege Escalation Workflow
1. **Target Identification**: Identify administrative operation `DELETE /api/v1/admin/users/42` reserved for `Role: Admin`.
2. **Low-Privilege Execution**: Transmit identical HTTP request using `Role: User` authentication token.
3. **Response Evaluation**: Server returns HTTP `200 OK` and executes user deletion, violating function-level boundaries.

#### Expected Safe Response vs. Vulnerable Behavior
* **Expected Safe Response**: HTTP `401 Unauthorized` (if unauthenticated) or HTTP `403 Forbidden` (if authenticated with insufficient privileges).
* **Vulnerable Behavior**: HTTP `200 OK`, `201 Created`, or `204 No Content` indicating successful execution of the administrative function by a low-privileged actor.

#### Evidence Requirements
* Role authorization matrix defining permitted endpoints and HTTP methods per role.
* HTTP request sent by low-privileged actor targeting the administrative endpoint.
* Server response headers, status code, and before-and-after system state diff proving function execution.

#### Automated Verification Oracle
```
Oracle_BFLA(Request, Response, RoleMatrix):
  AllowedRoles = RoleMatrix.GetAllowedRoles(Request.Endpoint, Request.Method)
  IF Request.Actor.Role NOT IN AllowedRoles:
    IF Response.StatusCode IN [200, 201, 202, 204]:
      RETURN FAIL("BFLA Violation: Restricted Function Executed by Low-Privilege Role")
  RETURN PASS
```

---

### 3.4 Unrestricted Access to Sensitive Business Flows (Workflow Abuse)

* **Industry Standards Mapping**: OWASP API6:2023 | CWE-799 (Improper Control of Interaction Frequency), CWE-840 (Business Logic Errors)
* **Description & Threat Mechanism**: This category addresses vulnerabilities where an API exposes a sensitive business flow—such as purchasing an item, issuing a coupon code, submitting a referral, or booking a reservation—without enforcing rate limits, velocity checks, or state sequence invariants. Attackers exploit these endpoints through automated execution to exhaust inventory, manipulate financial rewards, or bypass intermediate workflow steps (e.g., jumping directly to `Order Fulfillment` without completing `Payment Processing`).

#### Operational Criteria & Preconditions
* **Precondition 1 (Business Workflow Definition)**: A multi-step state graph defines sequential transitions: $S_0 \xrightarrow{Req_1} S_1 \xrightarrow{Req_2} S_2 \xrightarrow{Req_3} S_3$ (e.g., `Cart Creation` $\rightarrow$ `Checkout` $\rightarrow$ `Payment` $\rightarrow$ `Receipt`).
* **Precondition 2 (State Transition Bypass Attack)**: Actor $A_1$ issues request $Req_3$ (`Receipt / Fulfillment`) while the object remains in state $S_0$ or $S_1$, skipping required payment verification $Req_2$.
* **Precondition 3 (Automated Velocity Attack)**: Actor $A_1$ executes high-value business request $Req_{business}$ in automated rapid succession ($N > Threshold$) within time window $\Delta t$, exhausting finite business resources or accumulating unauthorized benefits.

#### Workflow State Bypass Sequence
1. **Initial State**: Order object remains in State $S_0$ (`Cart Creation`).
2. **Bypass Request**: Attacker issues direct request to `POST /api/v1/orders/101/fulfill` ($Req_3$), skipping `POST /api/v1/orders/101/pay` ($Req_2$).
3. **State Violation**: Server transitions order directly to State $S_3$ (`Fulfilled`), processing order without payment.

#### Expected Safe Response vs. Vulnerable Behavior
* **Expected Safe Response**: HTTP `400 Bad Request` or `409 Conflict` (for state transition rule violations), or HTTP `429 Too Many Requests` (when velocity thresholds are exceeded).
* **Vulnerable Behavior**: HTTP `200 OK` confirming state transition despite skipping mandatory intermediate preconditions, or unbounded execution of business actions.

#### Evidence Requirements
* Sequence graph detailing required state ordering, preconditions, and postconditions.
* Multi-request HTTP trace capturing attempted state-skipping or high-velocity execution logs.
* Database state history demonstrating invalid state progression or resource depletion.

#### Automated Verification Oracle
```
Oracle_BusinessFlow(Request, Response, CurrentState, WorkflowRules):
  IF Request.TargetTransition NOT IN WorkflowRules.ValidTransitions(CurrentState):
    IF Response.StatusCode IN [200, 201, 202, 204]:
      RETURN FAIL("Business Flow Violation: Invalid State Transition Executed")
  IF Request.ExecutionVelocity > WorkflowRules.MaxVelocityThreshold:
    IF Response.StatusCode != 429:
      RETURN FAIL("Business Flow Abuse: Rate/Velocity Limit Unenforced")
  RETURN PASS
```

---

## 4. Verification Oracles & Decision Rules Matrix

The table below summarizes the four focused vulnerability families, detailing their standard mappings, state precondition requirements, expected safe responses, and primary verification oracle types.

| Vulnerability Category | OWASP API 2023 | Primary CWE Mapping | Topological Preconditions | Expected Safe Response | Verification Oracle Type |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Broken Object Level Authorization (BOLA)** | API1:2023 | CWE-284, CWE-639 | Actor $A_2$ executes request targeting Object $o_1$ owned by Actor $A_1$ or Tenant $T_2$ | `403 Forbidden` / `404 Not Found` | Differential Authorization Oracle |
| **Broken Object Property Authorization (BOPLA)** | API3:2023 | CWE-213, CWE-915 | Actor $A_1$ includes $P_{restricted}$ in payload or requests sensitive property schema | `400 Bad Request` / `200 OK` (Properties Filtered) | Property Diff & Schema Invariant Oracle |
| **Broken Function Level Authorization (BFLA)** | API5:2023 | CWE-285 | Actor $A_{user}$ invokes administrative endpoint $F_{admin}$ or privileged HTTP method | `401 Unauthorized` / `403 Forbidden` | Role Hierarchy Matrix Oracle |
| **Unrestricted Access to Sensitive Business Flows** | API6:2023 | CWE-799, CWE-840 | Actor $A_1$ skips mandatory workflow step $S_k$ or exceeds action velocity $V_{max}$ | `400 Bad Request` / `409 Conflict` / `429 Too Many` | Business State Invariant Oracle |

---

## 5. Evidence Schema & Redaction Standards

To enable reproducible verification and support Human-in-the-Loop (HITL) triage, all security test findings must be serialized according to a standardized, normalized evidence schema.

### Normalized Evidence JSON Schema Structure

```json
{
  "finding_id": "FINDING-2026-BOLA-001",
  "vulnerability_category": "BOLA",
  "owasp_mapping": "API1:2023",
  "cwe_mapping": "CWE-639",
  "target_endpoint": "/api/v1/tenants/10/documents/1005",
  "http_method": "GET",
  "test_context": {
    "primary_actor": {"user_id": "u-101", "role": "user", "tenant_id": "t-01"},
    "attacking_actor": {"user_id": "u-202", "role": "user", "tenant_id": "t-02"}
  },
  "evidence_trace": [
    {
      "step": 1,
      "action": "OBJECT_CREATION",
      "request": {
        "method": "POST",
        "url": "https://api.cyberrange.local/api/v1/tenants/01/documents",
        "headers": {"Authorization": "Bearer [REDACTED_TOKEN_A1]"},
        "body": {"title": "Confidential Report"}
      },
      "response": {
        "status_code": 201,
        "body": {"id": 1005, "tenant_id": "t-01", "title": "Confidential Report"}
      }
    },
    {
      "step": 2,
      "action": "CROSS_TENANT_ACCESS_ATTEMPT",
      "request": {
        "method": "GET",
        "url": "https://api.cyberrange.local/api/v1/tenants/10/documents/1005",
        "headers": {"Authorization": "Bearer [REDACTED_TOKEN_A2]"},
        "body": null
      },
      "response": {
        "status_code": 200,
        "body": {"id": 1005, "tenant_id": "t-01", "title": "Confidential Report"}
      }
    }
  ],
  "state_diff": {
    "before": {"document_id": 1005, "read_count": 0},
    "after": {"document_id": 1005, "read_count": 1}
  },
  "oracle_evaluation": {
    "oracle_name": "DifferentialAuthorizationOracle",
    "result": "FAIL",
    "reason_code": "REASON_CROSS_TENANT_READ_ALLOWED"
  },
  "provenance": {
    "seed": 42,
    "timestamp": "2026-10-30T07:15:00Z",
    "raw_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
}
```

### Mandatory Redaction Rules

1. **Tokens & Cookies**: All HTTP `Authorization` headers, session cookies (`Set-Cookie`), and JWT signatures must be automatically replaced with standard tokens (`[REDACTED_BEARER_TOKEN]`, `[REDACTED_COOKIE]`).
2. **Personally Identifiable Information (PII)**: Real or synthetic email addresses, phone numbers, and cryptographic secret keys within JSON response bodies must be masked.
3. **Cryptographic Integrity**: The `raw_hash` field records the SHA-256 digest of the unredacted payload stream prior to sanitization, guaranteeing auditability and tamper-evident provenance without exposing sensitive credentials in reports.
