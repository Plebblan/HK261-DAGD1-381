# Systematic Survey and Research Boundary Specification

## 1. Executive Research Objective & Task Overview

### 1.1 Objective and Scope
The primary objective of this systematic survey is to establish an academically defensible, technically rigorous research boundary for **Phase 1** of the Stateful API Security Testing Project. Rather than functioning solely as a passive literature review, this document establishes a formal capability baseline to distinguish solved security-testing problems from unresolved research challenges.

The survey addresses four core research questions:
1. **Existing Coverage**: What API security vulnerabilities, testing methodologies, automation tools, and benchmark applications are already addressed by established standards and literature?
2. **Current Tool Capabilities**: Which specific sequence-generation and property-testing capabilities are natively provided by state-of-the-art tools such as RESTler and Schemathesis?
3. **Identified Research Gaps**: What critical capabilities remain missing for stateful authorization and business-logic testing involving multi-actor topologies, session boundaries, object ownership, tenant relationships, and business state transitions?
4. **Phase Boundary Allocation**: Which system components must be implemented in the deterministic Phase 1 foundation, and which components belong to the AI-assisted Phase 2 planner?

```text
Literature / Standard Survey
        ↓
Claim Extraction
        ↓
Evidence Verification
        ↓
Capability Comparison
        ↓
Research Gap
        ↓
Non-overlap Analysis
        ↓
RQ / Non-goal / Threat Model Freeze
        ↓
Phase 1 Boundary
```

---

## 2. Comprehensive Survey Scope & Reference Mapping

The survey encompasses seven distinct domain groups. Each group provides specific inputs to the project's vulnerability taxonomy, testing methodology, or experimental baseline.

| Group | Reference / Primary Source | Main Purpose & System Impact |
| :--- | :--- | :--- |
| **API Security Standard** | [OWASP API Security Top 10 Project](https://github.com/OWASP/API-Security/tree/master) | Defines core API authorization and business-flow risk taxonomies (BOLA, BOPLA, BFLA, Business Flow abuse). |
| **Testing Methodology** | [OWASP WSTG Framework](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Reconnaissance_for_Information_Leakage.md) | Defines established authorization testing procedures (`WSTG-ATHZ-02`) and delineates reconnaissance non-goals (`WSTG-INFO-01`). |
| **Authorization Automation** | Academic Literature & Regression Tooling | Identifies existing approaches for automated access-control testing and RBAC/ABAC policy regression. |
| **Testing Standards** | NIST SP 800-115 | Establishes principles for controlled execution, safety gateways, evidence collection, and audit repeatability. |
| **Stateful API Fuzzing** | Microsoft RESTler | Analyzes specification-driven dependency inference and stateful request-sequence generation. |
| **Schema-Based Testing** | Schemathesis | Analyzes OpenAPI/GraphQL property-based testing and generic status-code validation baselines. |
| **Benchmark Cyber Range** | OWASP crAPI / WebGoat / Juice Shop | Evaluates intentionally vulnerable microservice environments for ground-truth benchmark experiments. |

---

## 3. Survey A: OWASP API Security Top 10 Taxonomy

### 3.1 Primary Reference Integration
The project adopts the authoritative taxonomy from the [OWASP API Security Top 10 Repository](https://github.com/OWASP/API-Security/tree/master) to classify authorization and business-logic flaws. Phase 1 focuses specifically on four critical risk categories where stateful context is required for detection.

* **API1:2023 – Broken Object Level Authorization (BOLA)**: Occurs when an API endpoint exposes object identifiers without validating whether the requesting actor holds legitimate ownership or authorization over the target object.
* **API3:2023 – Broken Object Property Level Authorization (BOPLA)**: Occurs when an API allows an actor to read or modify specific object properties (excessive data disclosure or mass assignment) without field-level authorization checks.
* **API5:2023 – Broken Function Level Authorization (BFLA)**: Occurs when function-level access controls are improperly enforced, allowing a lower-privileged role to execute administrative or restricted functions.
* **API6:2023 – Unrestricted Access to Sensitive Business Flows**: Occurs when an API exposes a sensitive business workflow without enforcing state-transition constraints or rate limits, allowing adversaries to bypass required workflow steps.

### 3.2 Required Application Context & Taxonomy Mapping

To reliably detect OWASP API Top 10 flaws, the testing engine requires specific semantic model dimensions beyond standard OpenAPI schemas.

| OWASP API Risk | Project Interpretation | Required Semantic Context | Detection Oracle Mechanics |
| :--- | :--- | :--- | :--- |
| **API1:2023 (BOLA)** | Cross-user object access violation | `Actor` + `Session` + `Object` + `Owner` | Differential Oracle: Compare response when `Actor != Owner` against expected `403 Forbidden`. |
| **API3:2023 (BOPLA)** | Unauthorized property read/write | `Actor` + `Object` + `Property Schema` | Property Oracle: Detect unauthorized field disclosure or field modification in response payload. |
| **API5:2023 (BFLA)** | Cross-role function execution | `Actor` + `Role` + `Action Endpoint` | Role-Matrix Oracle: Evaluate `Actor.Role` against function permission matrix. |
| **API6:2023 (Flows)** | Invalid state sequence execution | `Actor` + `Business State` + `Sequence Graph` | State Invariant Oracle: Validate whether `State_Before -> Action -> State_After` represents a valid transition. |

### 3.3 Pipeline Mapping Strategy
The taxonomy mapping enforces a strict lineage from risk definition to evidence collection:
$$\text{OWASP API Risk} \longrightarrow \text{Security Property} \longrightarrow \text{Required Model} \longrightarrow \text{Differential Oracle} \longrightarrow \text{Normalized Evidence}$$

---

## 4. Survey B: OWASP WSTG Authorization & Information Gathering Framework

### 4.1 Primary Reference Integration
The project evaluates practical penetration-testing methodologies documented in the [OWASP Web Security Testing Guide (WSTG)](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Reconnaissance_for_Information_Leakage.md). This review serves two key purposes:
1. Converting manual authorization testing procedures into automated, deterministic API test sequences.
2. Delineating passive reconnaissance activities from active API security testing to freeze Phase 1 non-goals.

### 4.2 Authorization Testing Conversion (`WSTG-ATHZ`)
Section `WSTG-ATHZ-02` details manual procedures for testing privilege escalation, authorization schema bypass, and Insecure Direct Object References (IDOR). The survey establishes how these manual checks translate into automated test cases within the Role–Session–Object model.

| WSTG Test Case | Manual Tester Procedure | Automated Test Conversion Strategy | Automation Potential |
| :--- | :--- | :--- | :--- |
| **Bypass Authorization Schema** | Switch request headers manually to access protected resources. | Replay workflow with alternate role sessions across the Role Matrix. | **High (Phase 1)** |
| **Privilege Escalation** | Call administrative endpoints using lower-privileged user session tokens. | Automated cross-role function execution with privilege differential validation. | **High (Phase 1)** |
| **IDOR / BOLA** | Substitute resource ID in URL/body with another user's object ID. | Cross-User Object Swap across session tokens with ownership tracking. | **High (Phase 1)** |

### 4.3 Reconnaissance Mapping and Phase 1 Boundary Analysis
The WSTG framework includes information-gathering modules, such as [WSTG-INFO-01: Conduct Search Engine Reconnaissance for Information Leakage](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Reconnaissance_for_Information_Leakage.md).

**Boundary Determination**: Search engine reconnaissance, public OSINT, domain enumeration, and external information-leakage harvesting are explicitly classified as **Out of Scope (Phase 1 Non-Goals)**. 

* **Rationale**: Phase 1 focuses strictly on deterministic, reproducible, stateful API authorization and business-logic testing within a controlled Cyber Range environment. External reconnaissance does not contribute to evaluating stateful authorization or business-state transitions and introduces non-deterministic external dependencies.

---

## 5. Survey C: Automated Authorization Testing & Regression Literature

### 5.1 Objective and Search Strategy
This survey segment examines existing tools and academic literature designed to automate access-control testing and RBAC/ABAC policy regression. The search targeted literature across multiple domain keywords:
* *"automated authorization testing"*
* *"API access control regression"*
* *"cross-user authorization testing"*
* *"BOLA/IDOR detection automation"*
* *"stateful access control verification"*

### 5.2 Comparative Analysis Dimension
To evaluate whether existing automation tools solve the project's target problem, tools were assessed across twelve analytical dimensions:

```text
Traditional Authorization Testing          Stateful Multi-Actor Testing
     (Single Actor / Statics)                     (Proposed Framework)
┌────────────────────────────────┐           ┌────────────────────────────────┐
│ • Single user token            │           │ • Multi-actor topologies       │
│ • Static endpoint checks       │    vs     │ • Object ownership tracking    │
│ • Status code checks (401/403) │           │ • Tenant boundary isolation    │
│ • Stateless request execution │           │ • Business state transitions   │
└────────────────────────────────┘           └────────────────────────────────┘
```

### 5.3 Research Gap Identification
The survey reveals that while existing tools automate static endpoint access checks, they fail to simultaneously combine:
$$\text{Multi-Actor Topologies} + \text{Object Ownership} + \text{Tenant Isolation} + \text{Business State Graphs} + \text{Differential Oracles}$$

Existing solutions either test static role-based permissions without state context or test sequence execution without multi-tenant object ownership tracking.

---

## 6. Survey D: NIST SP 800-115 Methodological Foundation

NIST SP 800-115 (*Technical Guide to Information Security Testing and Assessment*) provides the organizational and operational framework for execution control, evidence preservation, and auditability.

| NIST SP 800-115 Principle | Project System Implementation |
| :--- | :--- |
| **Test Planning & Scope Control** | Formalized Threat Model and frozen Phase 1 research scope. |
| **Controlled Execution Environment** | **Safety Gateway** enforcing rate limits, IP allowlists, dry-run, and kill switch. |
| **Evidence Collection** | Standardized JSON Evidence Schema recording full request/response headers and payload state. |
| **Finding Analysis & Triage** | Deterministic Differential Oracles comparing expected vs. observed status and payload. |
| **Repeatability & Auditability** | Cyber Range reset scripts (database seed/reset) ensuring 100% reproducible test runs. |

---

## 7. Survey E: RESTler Stateful API Fuzzing Analysis

### 7.1 System Capability Review
RESTler (developed by Microsoft Research) represents the state of the art in specification-driven stateful API fuzzing. It parses OpenAPI specifications to infer producer-consumer dependencies (e.g., matching a `POST /orders` response `order_id` to a `GET /orders/{order_id}` request parameter) and dynamically generates request sequences.

### 7.2 Non-Overlap Analysis
While RESTler excels at stateful sequence generation for single-user functional testing, it lacks explicit primitives for multi-actor authorization differential testing.

| System Capability | Microsoft RESTler | Proposed Phase 1 System |
| :--- | :---: | :---: |
| **OpenAPI Specification Parsing** | Yes | Yes |
| **Producer-Consumer Dependency Inference** | Yes | Yes |
| **Single-Session Stateful Sequences** | Yes | Yes |
| **Multi-Actor Role Topologies** | Limited / Unsupported | **Core Requirement** |
| **Object Ownership & Tenant Modeling** | Outside Scope | **Core Requirement** |
| **Differential Authorization Oracle** | Plugin-dependent | **Core Requirement** |
| **Business State Transition Graphs** | Partial (Schema-based) | **Core Requirement** |
| **AI-Assisted Sequence Planner** | No | **Phase 2 Scope** |

---

## 8. Survey F: Schemathesis Schema-Driven Property Testing

Schemathesis provides schema-based property-based testing by generating input payloads from OpenAPI/GraphQL specs and validating generic server responses (e.g., detecting HTTP 500 crashes or schema mismatch).

```text
Schemathesis Baseline:
OpenAPI Schema ──> Property Generator ──> Single Request ──> Generic Check (500 Error)

Proposed Stateful Engine:
Role Matrix + Session Topology + Business State Graph ──> Replay Sequence ──> Differential Oracle
```

**Key Finding**: Schema-driven property testing cannot discover BOLA, BOPLA, or business-logic sequence bypasses without an explicit model of actor identities, object ownership boundaries, and business state invariants.

---

## 9. Survey G: Vulnerable Laboratory Applications (Cyber Range Candidates)

To establish a reproducible experimental benchmark, three intentionally vulnerable applications were evaluated as potential Cyber Range lab targets.

### 9.1 OWASP crAPI (Completely Ridiculous API)
* **Architecture**: Microservices-based application deployed via Docker Compose.
* **Vulnerability Profile**: Contains native BOLA (API1), BOPLA (API3), BFLA (API5), and multi-step business logic vulnerabilities (API6) in vehicle management and order workflows.
* **Evaluation Result**: Selected as the primary Cyber Range benchmark for Phase 1 due to its realistic multi-tenant data model and automated database seed/reset capabilities.

### 9.2 OWASP WebGoat & OWASP Juice Shop
* **Evaluation Result**: WebGoat and Juice Shop provide excellent educational lessons but lack native multi-tenant microservice APIs with complex state graphs. They are retained as secondary test benches for specific role-escalation test cases.

---

## 10. Claim–Evidence & Non-Overlap Matrices

### 10.1 Claim–Evidence Matrix
Every core research assertion in the project is anchored directly in literature or standards evidence.

| Claim ID | Core Assertion | Primary Source | Evidence Location / Reference | Confidence |
| :--- | :--- | :--- | :--- | :--- |
| **C01** | BOLA is the top API-specific authorization vulnerability. | OWASP API Security | [OWASP API Top 10 Repo](https://github.com/OWASP/API-Security/tree/master) (API1:2023) | High |
| **C02** | WSTG defines manual procedures for cross-role privilege testing. | OWASP WSTG | [WSTG Framework](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Reconnaissance_for_Information_Leakage.md) (`WSTG-ATHZ-02`) | High |
| **C03** | Passive search engine reconnaissance is distinct from active API testing. | OWASP WSTG | `WSTG-INFO-01` Reconnaissance Guide | High |
| **C04** | RESTler automatically infers producer-consumer data dependencies. | Microsoft Research | RESTler Research Paper & Repository | High |
| **C05** | Schemathesis performs property testing without multi-actor state tracking. | Schemathesis Documentation | Schemathesis Open-Source Core | High |
| **C06** | OWASP crAPI provides reproducible multi-tenant microservice BOLA benchmarks. | OWASP crAPI | OWASP crAPI Repository & Docker Spec | High |

### 10.2 Non-Overlap Matrix
Comparison of the proposed system against existing tools and benchmarks.

| Capability Dimension | OWASP WSTG | RESTler | Schemathesis | OWASP crAPI | Proposed System |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **API Schema Parsing** | Manual | Yes | Yes | Benchmark | **Yes** |
| **Stateful Sequence Generation** | Manual | Yes | Partial | Benchmark | **Yes** |
| **Multi-Actor Identity Modeling** | Manual | No | No | Benchmark | **Core (Phase 1)** |
| **Object Ownership Tracking** | Manual | No | No | Benchmark | **Core (Phase 1)** |
| **Tenant Boundary Isolation** | Manual | No | No | Benchmark | **Core (Phase 1)** |
| **Business State Transition Graphs** | Manual | Partial | No | Benchmark | **Core (Phase 1)** |
| **Differential Authorization Oracle** | Manual | Plugin | No | Ground Truth | **Core (Phase 1)** |
| **Controlled Safety Gateway** | Methodology | No | No | N/A | **Core (Phase 1)** |
| **AI Sequence Planner & Ranker** | N/A | No | No | N/A | **Phase 2 Scope** |
| **Human-in-the-Loop (HITL) Triage** | N/A | No | No | N/A | **Phase 2 Scope** |

---

## 11. Research Gap Statement & Capability Composition

The formal research gap addressed by this project is defined through **capability composition**:

$$\text{Research Gap} = \left( \begin{array}{c} \text{Multi-Actor Topology} + \text{Role-Session Model} + \text{Object Ownership} \\ + \text{Tenant Isolation} + \text{Business State Graph} + \text{Multi-Step Workflow} \\ + \text{Differential Authorization Oracle} + \text{Reproducible Cyber Range Reset} \end{array} \right)$$

No single existing tool or testing framework provides this unified, reproducible testing engine. The contribution of Phase 1 is the construction and validation of this **deterministic stateful authorization testing foundation**.

---

## 12. Boundary Freeze Specifications

### 12.1 Frozen Research Questions (RQs)
* **RQ1 (Semantic Modeling)**: How can Role–Session–Object topologies and Business State Graphs be formally modeled from OpenAPI specifications and traffic logs to represent multi-actor authorization constraints?
* **RQ2 (Stateful Workflow Execution)**: How can multi-actor, multi-state request workflows be captured, replayed, and executed reproducibly within a controlled Cyber Range environment?
* **RQ3 (Deterministic Verification)**: How can deterministic Differential Authorization and State Invariant Oracles be constructed to reliably detect BOLA, BOPLA, BFLA, and business-flow bypasses without high false-positive rates?
* **RQ4 (Phase 2 Research Question - AI & HITL)**: What is the quantitative impact of AI-assisted test sequence planning and Human-in-the-Loop (HITL) triage on vulnerability discovery precision and verification overhead? *(Deferred to Phase 2)*.

### 12.2 Frozen Non-Goals (Out of Scope for Phase 1)
To ensure project execution remains disciplined and defensible, the following areas are frozen as **Out of Scope**:
1. **General Vulnerability Scanning**: SQL Injection, Reflected/Stored XSS, Command Injection, SSRF, and generic memory corruption testing.
2. **Reconnaissance & OSINT**: External search engine reconnaissance ([WSTG-INFO-01](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Reconnaissance_for_Information_Leakage.md)), domain asset discovery, passive intelligence gathering, and external target enumeration.
3. **Autonomous AI Penetration Testing**: Fully autonomous LLM exploit chain generation, unconstrained AI agent execution, and self-directed target discovery.
4. **Autonomous Oracle Inference**: Generalized, application-agnostic business logic inference without human validation.

### 12.3 Frozen Threat Model
* **Attacker Profile**: Authenticated or partially authenticated API user operating with valid credentials across defined roles, sessions, and tenants.
* **Target Application**: Authorized microservice web application (OWASP crAPI) executing inside an isolated Docker Cyber Range.
* **Attacker Capabilities**: Modifying request headers/parameters, swapping session tokens, changing workflow sequence ordering, attempting cross-tenant object access, and executing unauthorized functions.
* **Safety & Security Boundary**: All generated test traffic must pass through the **Safety Gateway**, enforcing host allowlists, request frequency limits, dry-run mode, emergency kill switch, and full HTTP audit logging.

```text
Test Generator ──> Safety Gateway [Allowlist / Rate Limit / Kill Switch] ──> Cyber Range Target ──> Audit Log
```

### 12.4 Frozen AI-Use Conditions
* **Phase 1 (Deterministic Foundation)**: AI tools may be used solely as offline development aids (e.g., assisting in drafting documentation, generating initial YAML schema candidates). AI outputs **must not** automatically become canonical ground truth without human validation.
* **Phase 2 (AI-Assisted Planning)**: AI models will be introduced strictly for sequence planning, candidate ranking, and HITL prioritization under explicit logging and budget constraints.

---

## 13. Final Survey Deliverables & Definition of Done

### 13.1 Eight Required Survey Artifacts
1. **Survey Notes**: Summary notes across OWASP, WSTG, NIST, RESTler, Schemathesis, and Lab benchmarks.
2. **OWASP Taxonomy Matrix**: Mapping OWASP risks to required models, oracles, and evidence schemas.
3. **Claim–Evidence Matrix**: Formal mapping connecting every academic claim to verifiable sources.
4. **Related-Work Matrix**: Comparative evaluation of stateful fuzzing and property testing literature.
5. **Non-Overlap Matrix**: Explicit capability matrix differentiating the proposed system from existing tools.
6. **Research Gap Statement**: Formal capability composition gap statement.
7. **Boundary Freeze Document**: Frozen RQs, Non-Goals, Threat Model, and AI-Use Rules.
8. **Phase 1 Survey Specification**: Final approved specification report (`survey_and_boundary_spec.md`).

### 13.2 Definition of Done Checklist
* [x] OWASP API Security Top 10 (2023) mapped to project flaw taxonomy.
* [x] OWASP WSTG authorization procedures (`WSTG-ATHZ-02`) mapped to automated test candidates, and reconnaissance (`WSTG-INFO-01`) frozen as out-of-scope.
* [x] RESTler and Schemathesis analyzed for sequence and property-testing limits.
* [x] NIST SP 800-115 integrated for testing controls, evidence schemas, and safety boundaries.
* [x] OWASP crAPI validated as primary Cyber Range benchmark target.
* [x] Claim–Evidence Matrix and Non-Overlap Matrix fully populated.
* [x] Research Questions, Non-Goals, Threat Model, and AI-Use Conditions officially frozen for Phase 1.
