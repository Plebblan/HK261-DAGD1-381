# Task 1 - Systematic Survey and Boundary Validation

## 1. Objective

The purpose of this survey is not only to review existing security-testing techniques, but to establish a **defensible research boundary** for Phase 1.

The survey must answer four questions:

1. What is already covered by existing security standards, testing methodologies, automation tools, and vulnerable applications?
2. Which capabilities are already available in tools such as RESTler and Schemathesis?
3. What capabilities are still missing for **stateful authorization and business-logic testing involving multiple actors, sessions, objects, tenants, and business states**?
4. Which parts of the proposed system belong to Phase 1, and which should be reserved for Phase 2?

The final output should therefore consist of:

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

# 2. Survey Scope

The survey should cover the following seven groups.

| Group                        | Source                                                             | Main Purpose                                                    |
| ---------------------------- | ------------------------------------------------------------------ | --------------------------------------------------------------- |
| API Security Standard        | OWASP API Security Top 10 2023                                     | Define relevant API authorization/business-flow risks           |
| Security Testing Methodology | OWASP WSTG Authorization Testing                                   | Define established authorization-testing procedures             |
| Automation / Regression      | Authorization Testing Automation / Regression literature and tools | Identify existing automated authorization-testing approaches    |
| Security Testing Methodology | NIST SP 800-115                                                    | Establish testing, assessment, evidence, and process principles |
| Stateful API Fuzzing         | RESTler                                                            | Analyze stateful request-sequence generation                    |
| Schema-Based Testing         | Schemathesis                                                       | Analyze OpenAPI-driven property-based API testing               |
| Vulnerable Applications      | crAPI / WebGoat / Juice Shop                                       | Analyze existing benchmark/lab capabilities                     |

---

# 3. Survey A - OWASP API Security Top 10 2023

## 3.1 Objective

Use OWASP API Security Top 10 2023 as the primary reference for defining the project's vulnerability taxonomy.

The survey should focus particularly on:

* API1:2023 - Broken Object Level Authorization (BOLA)
* API3:2023 - Broken Object Property Level Authorization (BOPLA)
* API5:2023 - Broken Function Level Authorization (BFLA)
* API6:2023 - Unrestricted Access to Sensitive Business Flows

OWASP describes API1 as object-level authorization weaknesses, API3 as improper authorization at the object-property level, API5 as function-level authorization weaknesses, and API6 as abuse of sensitive business flows.

## 3.2 What to Extract

For each relevant category, record:

```text
Definition
Attack condition
Required application context
Typical attack pattern
Expected security property
Detection evidence
Limitations
Relation to project taxonomy
```

Example:

| Risk                    | Project Interpretation             | Required Context          |
| ----------------------- | ---------------------------------- | ------------------------- |
| BOLA                    | Cross-user object access           | Actor + Object + Owner    |
| BOPLA                   | Unauthorized property read/write   | Actor + Object + Property |
| BFLA                    | Unauthorized function/action       | Actor + Role + Action     |
| Sensitive Business Flow | Invalid/abusive workflow execution | Actor + State + Sequence  |

## 3.3 Expected Output

Produce:

**`OWASP-API-Taxonomy.md`**

containing the mapping:

```text
OWASP API Risk
      ↓
Security Property
      ↓
Required Model
      ↓
Oracle
      ↓
Evidence
```

This document becomes the basis for the vulnerability taxonomy in Phase 1.

---

# 4. Survey B - OWASP WSTG Authorization Testing

## 4.1 Objective

Use WSTG to determine what authorization testing already looks like from a practical penetration-testing perspective.

The WSTG authorization section includes testing for bypassing authorization schemas, privilege escalation, and insecure direct object references.

In particular, WSTG-ATHZ-02 examines whether authenticated users can access resources or perform functions belonging to another role/privilege, including horizontal and vertical privilege escalation.

## 4.2 What to Extract

For each authorization test:

```text
Tester prerequisite
Actor / role
Target resource
Action
Expected authorization
Attack variation
Observed evidence
Human verification requirement
Automation potential
```

Build a table such as:

| WSTG Test                   | Actor                 | Target                      | Expected Property         | Automation Potential |
| --------------------------- | --------------------- | --------------------------- | ------------------------- | -------------------- |
| Bypass authorization schema | Different roles       | Protected resource/function | Unauthorized actor denied | High                 |
| Privilege escalation        | Lower privilege actor | Higher privilege function   | Lower role denied         | High                 |
| IDOR                        | Different user        | Another user's object       | Object access denied      | High                 |

## 4.3 Important Research Question

The survey should explicitly ask:

> **Which parts of WSTG authorization testing can be converted from manual tester procedures into deterministic, replayable API test cases?**

This directly supports the project's:

* Role–Session–Object model
* Workflow capture
* Replay harness
* Authorization oracle

---

# 5. Survey C - Authorization Testing Automation / Regression

## 5.1 Objective

This part should investigate existing approaches that automate authorization testing or continuously regression-test authorization policies.

The goal is to identify whether existing systems already provide:

```text
Role Matrix
+
Multiple Identities
+
Cross-User Object Testing
+
Policy Regression
+
Stateful Workflows
+
Evidence
```

## 5.2 Search Categories

Do not search only for the exact phrase "authorization testing automation".

Search across:

```text
"automated authorization testing"
"authorization regression testing"
"API authorization testing"
"access control testing automation"
"cross-user authorization testing"
"RBAC testing"
"ABAC testing"
"IDOR detection automation"
"BOLA detection"
"API access control testing"
"authorization policy regression"
```

## 5.3 Information to Extract

For every relevant work/tool:

| Dimension    | Question                                         |
| ------------ | ------------------------------------------------ |
| Input        | OpenAPI? traffic? source code? policy?           |
| Identity     | One actor or multiple actors?                    |
| Roles        | RBAC? arbitrary identities?                      |
| Objects      | Does it track ownership?                         |
| Tenants      | Does it model tenant isolation?                  |
| State        | Does it model business states?                   |
| Sequence     | Single request or multi-step workflow?           |
| Oracle       | How is violation detected?                       |
| Regression   | Can tests be replayed after application changes? |
| Ground Truth | Are vulnerabilities known and verifiable?        |
| Evidence     | What evidence is produced?                       |
| AI           | Is an LLM/ML component involved?                 |

## 5.4 Main Goal

The important comparison is:

```text
Traditional Authorization Regression
          vs.
Stateful Authorization Testing
```

The research gap should not be claimed merely because "automation exists".

Instead, identify precisely whether existing approaches simultaneously address:

```text
Multi-actor
+
Object ownership
+
Tenant relationship
+
Business state
+
Multi-step sequence
+
Authorization oracle
+
Reproducible regression
```

---

# 6. Survey D - NIST SP 800-115

## 6.1 Objective

NIST SP 800-115 should be used as the methodological foundation for the testing process rather than as a source for the project's vulnerability taxonomy.

The document provides guidance for planning and conducting technical security testing, analyzing findings, and developing mitigation strategies. It emphasizes the benefits and limitations of testing techniques rather than prescribing a single testing program.

## 6.2 What to Extract

Focus on:

```text
Testing planning
Testing execution
Evidence collection
Finding analysis
Test limitations
Risk considerations
Documentation
Repeatability
```

## 6.3 How It Supports the Project

Map NIST principles to the system:

| NIST Principle     | Project Implementation          |
| ------------------ | ------------------------------- |
| Test planning      | Threat model + test scope       |
| Controlled testing | Safety Gateway                  |
| Evidence           | HTTP evidence schema            |
| Findings           | Candidate vulnerability records |
| Analysis           | Oracle + triage                 |
| Repeatability      | Seed + reset + replay           |
| Documentation      | Audit logs                      |
| Limitations        | Explicit Phase 1 non-goals      |

This prevents the project from becoming merely a collection of scripts without a defensible testing methodology.

---

# 7. Survey E - RESTler

## 7.1 Objective

RESTler is the most important related work for the **stateful API sequence** aspect of the project.

RESTler analyzes an API specification, infers producer-consumer dependencies between requests, and generates sequences of requests. It also uses dynamic feedback from previous executions to prune or expand the sequence search space.

## 7.2 What to Analyze

Extract:

```text
Input specification
Dependency inference
Request sequence generation
Dynamic feedback
Statefulness
Search-space reduction
Security-property checking
Coverage
Limitations
```

## 7.3 Non-Overlap Analysis

The comparison should explicitly answer:

> **What does RESTler already solve, and what does our project add?**

Potential comparison dimensions:

| Capability                         | RESTler                      | Proposed System  |
| ---------------------------------- | ---------------------------- | ---------------- |
| OpenAPI-driven testing             | Yes                          | Yes              |
| Request dependencies               | Yes                          | Yes              |
| Stateful sequences                 | Yes                          | Yes              |
| Producer-consumer relationships    | Yes                          | Yes              |
| Multiple authenticated actors      | Investigate                  | Core requirement |
| Role model                         | Investigate                  | Core             |
| Object ownership                   | Investigate                  | Core             |
| Tenant relationship                | Investigate                  | Core             |
| Authorization differential testing | Investigate                  | Core             |
| Business-state invariants          | Investigate                  | Core             |
| Evidence normalization             | Investigate                  | Core             |
| Authorization regression           | Investigate                  | Core             |
| AI Planner                         | Not the Phase-1 contribution | Phase 2          |
| HITL triage                        | Investigate                  | Phase 2          |

**Important:** items marked "Investigate" must be verified from the actual RESTler documentation/papers before becoming claims in the thesis. The survey must not assume absence merely because it is not obvious from the high-level description.

RESTler itself already supports a pluggable model for checking security properties, so the project's novelty should **not** be claimed as simply "adding security-property checking".

---

# 8. Survey F - Schemathesis

## 8.1 Objective

Schemathesis represents the **schema-driven property-based testing** baseline.

Its documentation describes generating many test cases from OpenAPI/GraphQL schemas, property-based inputs, response validation, status-code checks, server-error detection, and reproduction-ready failures.

## 8.2 What to Analyze

Extract:

```text
Schema coverage
Operation generation
Input generation
Property-based testing
Response validation
Negative testing
Reproducibility
Failure reporting
Sequence/state support
Authorization awareness
Business-logic awareness
```

## 8.3 Non-Overlap Question

The key question is:

> **What can schema-based property testing detect without an explicit actor–object–state model?**

This gives a useful baseline:

```text
Schemathesis
    ↓
Schema / Operation
    ↓
Generated Request
    ↓
Generic Property Check
```

versus the proposed stateful approach:

```text
Role
 +
Session
 +
Object
 +
Tenant
 +
Business State
       ↓
Workflow
       ↓
Request Sequence
       ↓
Authorization / State Oracle
```

The goal is **not** to claim Schemathesis cannot test authorization unless verified. Instead, the survey should determine exactly which authorization/state semantics must be explicitly provided to detect the target flaw families.

---

# 9. Survey G - Vulnerable Laboratory Applications

## 9.1 crAPI

crAPI is particularly relevant because it is an intentionally vulnerable, API-focused application designed around API security risks. OWASP describes it as a microservice-based application with API vulnerabilities and challenges that can require multiple steps.

Survey:

```text
Architecture
API specification
Roles
Users
Objects
Object ownership
Workflows
States
Authorization vulnerabilities
Business-flow vulnerabilities
Existing ground truth
Reset capability
Docker deployment
```

Main question:

> Can crAPI serve as an existing benchmark, or is a custom stateful range still necessary?

---

## 9.2 WebGoat

WebGoat is an intentionally insecure OWASP application designed as a learning environment for common application-security flaws.

Survey:

```text
Authorization lessons
Privilege escalation
IDOR
Workflow/business logic
Multi-user scenarios
API availability
Stateful behavior
Automation suitability
Ground-truth availability
Reset/reproducibility
```

Main question:

> Which WebGoat scenarios can be converted into automated authorization regression tests?

---

## 9.3 Juice Shop

Juice Shop is an intentionally insecure application used for security training, CTFs, demonstrations, and security-tool testing, and contains a broad set of application-security challenges.

Survey:

```text
Relevant authorization challenges
Object access
Privilege escalation
Business logic
API endpoints
Authentication/session behavior
Reproducibility
Docker support
Automation feasibility
```

Main question:

> Which Juice Shop scenarios are suitable as authorization/business-logic test cases rather than general vulnerability tests?

---

# 10. Claim–Evidence Matrix

This is a mandatory research artifact.

Every important statement in the thesis should have a source.

Use:

| ID  | Claim                                                    | Source            | Evidence Location | Evidence Type      | Confidence |
| --- | -------------------------------------------------------- | ----------------- | ----------------- | ------------------ | ---------- |
| C01 | BOLA is an API-specific authorization risk               | OWASP API Top 10  | API1              | Standard           | High       |
| C02 | WSTG defines practical authorization bypass testing      | OWASP WSTG        | WSTG-ATHZ-02      | Methodology        | High       |
| C03 | RESTler generates stateful request sequences             | RESTler paper     | Section X         | Research           | High       |
| C04 | RESTler infers producer-consumer dependencies            | RESTler paper     | Section X         | Research           | High       |
| C05 | Schemathesis generates property-based cases from OpenAPI | Schemathesis docs | Quick Start       | Tool documentation | High       |
| C06 | crAPI provides intentionally vulnerable API scenarios    | OWASP crAPI       | README            | Lab                | High       |
| C07 | Existing approach supports cross-user authorization      | Related work      | Exact evidence    | Research/tool      | To verify  |

### Rule

Do not write:

> "No existing tool can do X."

unless the survey provides sufficient evidence.

Instead write:

> "In the surveyed documentation/papers, we found no documented support for X."

This distinction is important for academic defensibility.

---

# 11. Non-Overlap Matrix

The second mandatory artifact is the **non-overlap matrix**.

Use the proposed system as the final column.

| Capability                 | WSTG |   RESTler | Schemathesis |             crAPI |           WebGoat |        Juice Shop | Proposed System |
| -------------------------- | ---: | --------: | -----------: | ----------------: | ----------------: | ----------------: | --------------: |
| API schema testing         |    △ |         ✓ |            ✓ |                 ✓ |                 △ |                 ✓ |               ✓ |
| Stateful sequences         |    △ |         ✓ |            △ |                 ✓ |                 ✓ |                 ✓ |               ✓ |
| Multiple actors            |    ✓ |         ? |            ? |                 ✓ |                 ✓ |                 ? |        **Core** |
| Role model                 |    ✓ |         ? |            ? |                 ✓ |                 ✓ |                 ✓ |        **Core** |
| Object ownership           |    ✓ |         ? |            ? |                 ✓ |                 ✓ |                 ✓ |        **Core** |
| Tenant isolation           |    ? |         ? |            ? |                 ? |                 ? |                 ? |        **Core** |
| Business state graph       |    △ |         △ |            ? |                 ✓ |                 ✓ |                 ✓ |        **Core** |
| Differential authorization |    ✓ |         ? |            ? | Scenario-specific | Scenario-specific | Scenario-specific |        **Core** |
| State invariant oracle     |    △ |         ? |            ? |      Ground truth |      Ground truth |      Ground truth |        **Core** |
| Evidence normalization     |    △ |         ✓ |            ✓ |                 ✓ |                 ✓ |                 ✓ |        **Core** |
| Reproducible reset         |    △ |         ✓ |            ✓ |                 ✓ |                 ✓ |                 ✓ |        **Core** |
| Authorization regression   |    △ |         ? |            ? |            Manual |            Manual |            Manual |        **Core** |
| AI Planner                 |    ✗ | ✗/limited |    ✗/limited |                 ✗ |                 ✗ |                 ✗ |     **Phase 2** |
| HITL evaluation            |    △ |         ? |            ? |             Human |             Human |             Human |     **Phase 2** |

Legend:

```text
✓ = explicitly supported
△ = partially related
? = requires verification
✗ = outside documented scope
```

The `?` cells must remain `?` until the survey produces evidence.

---

# 12. Research Gap Statement

After completing the matrices, the team should formulate the gap using **capability composition**, rather than claiming that individual components are new.

The proposed gap should be tested against the following combination:

```text
Multi-Actor
      +
Role
      +
Session
      +
Object Ownership
      +
Tenant
      +
Business State
      +
Multi-Step Workflow
      +
Differential Authorization
      +
State Invariant
      +
Reproducible Evidence
      +
Regression
```

The key question is:

> **Do existing standards, tools, and laboratory applications provide this combination as one reproducible testing framework?**

If the answer is not fully supported by the evidence, the contribution can be framed as **integrating these capabilities into a controlled, reproducible stateful authorization/business-logic testing foundation**, rather than claiming that each individual mechanism is novel.

---

# 13. Freeze RQs

After the survey, freeze the RQs.

### RQ1 - Stateful Modeling

> How can Role–Session–Object relationships and Business States be modeled from OpenAPI specifications and traffic data to represent the actor–object relationships and state transitions required for stateful authorization and business-logic testing?

### RQ2 - Stateful Workflow Replay and Verification

> How can multi-actor, multi-state workflows be captured, replayed, and verified in a reproducible and controlled Cyber Range environment?

### RQ3 - Reproducible Authorization and State Verification

> How can reproducible authorization and state-verification baselines be constructed to detect authorization and business-logic violations in stateful Web/API workflows?

### RQ4 - Phase 2 Research Question

> What is the quantitative impact of AI-assisted planning and Human-in-the-loop triage on detection precision and verification effort under a fixed testing budget?

RQ4 should remain a **Phase 2 question**, because Phase 1 is intended to establish the reproducible testing foundation and baselines rather than evaluate the final AI/HITL system. The project plan explicitly separates the Phase 1 foundation from the Phase 2 Planner/Ranker and HITL work.

---

# 14. Freeze Non-Goals

The following should be explicitly frozen as Phase 1 non-goals.

## Out of Scope

### General Vulnerability Discovery

```text
SQL Injection
XSS
Command Injection
SSRF
Generic fuzzing
Generic vulnerability scanning
```

unless required only as supporting context.

### Reconnaissance

```text
Internet-scale reconnaissance
Attack-surface discovery
Asset enumeration
External target discovery
```

### Advanced AI

```text
Autonomous LLM penetration testing
AI-based autonomous reconnaissance
AI-generated exploit chains
Fully autonomous planner
AI-based generalized vulnerability discovery
```

### Advanced Oracle Generation

```text
General semantic oracle generation
Application-independent business-logic inference
Fully autonomous security-policy inference
```

### HITL Optimization

```text
Large-scale user study
Human-factor optimization
Quantitative HITL improvement study
```

These belong to Phase 2.

---

# 15. Freeze Threat Model

The threat model should define:

## Attacker

```text
Authenticated or partially authenticated API user
```

with potentially:

```text
Different roles
Different sessions
Different tenants
Different object ownership
```

## Target

```text
Authorized Web/API application
```

running inside the controlled Cyber Range.

## Attacker Capabilities

The simulated attacker may:

```text
Modify request parameters
Replace object identifiers
Replay requests
Switch between authorized test accounts
Change request ordering
Attempt unauthorized state transitions
Attempt cross-role actions
Attempt cross-tenant object access
```

## Attacker Limitations

The simulated attacker does not:

```text
Escape the Cyber Range
Attack external systems
Perform unrestricted network reconnaissance
Attack infrastructure outside the allowlist
Use real user credentials
Use real personal data
```

## Security Boundary

All testing must occur through:

```text
Safety Gateway
      ↓
Allowlist
      ↓
Request Budget
      ↓
Target Application
      ↓
Audit Log
```

The existing project specification already requires the Phase 1 Safety Gateway, including allowlists, request limits, dry-run, kill switch, audit logging, and reset mechanisms.

---

# 16. Freeze AI-Use Conditions

This part is especially important because the project contains AI but Phase 1 should not become "an LLM wrapper."

## Phase 1

AI may be used for:

```text
Literature assistance
Document summarization
Candidate relationship extraction
Candidate state-transition extraction
Human-assisted labeling
Developer productivity
```

but AI-generated outputs must not automatically become ground truth.

### Required Rule

```text
AI Output
   ↓
Human Validation
   ↓
Canonical Model
```

The canonical:

```text
Role
Session
Object
State
Oracle
Ground Truth
```

must remain deterministic and reviewable.

## Phase 2

AI may be introduced for:

```text
Sequence generation
Sequence ranking
Planner reasoning
Candidate prioritization
HITL assistance
```

with explicit logging of:

```text
Prompt
Input Context
Model
Output
Reason Code
Selected Action
Final Human Decision
```

This creates a clean separation:

```text
Phase 1
Deterministic Foundation
        ↓
Phase 2
AI-assisted Planning
```

---

# 17. Final Survey Deliverables

At the end of Task 1, the team should have **eight concrete artifacts**.

```text
01. Survey Notes
    └── OWASP / WSTG / NIST / RESTler / Schemathesis / Labs

02. OWASP Taxonomy Matrix
    └── Vulnerability → Oracle → Evidence

03. Claim–Evidence Matrix
    └── Claim → Source → Exact Evidence

04. Related-Work Matrix
    └── Capability comparison

05. Non-Overlap Matrix
    └── Existing approaches vs Proposed System

06. Research Gap Statement
    └── Evidence-supported gap

07. Boundary Freeze
    ├── RQs
    ├── Non-goals
    ├── Threat Model
    └── AI-use Conditions

08. Phase-1 Survey Report
    └── Final approved version
```

---

# 18. Definition of Done

Task 1 is considered complete only when:

* [ ] OWASP API Security Top 10 2023 has been mapped to the project's flaw taxonomy.
* [ ] WSTG authorization procedures have been mapped to automated test candidates.
* [ ] Authorization automation/regression approaches have been surveyed.
* [ ] NIST SP 800-115 has been mapped to the testing methodology.
* [ ] RESTler has been analyzed for stateful sequence generation and dependencies.
* [ ] Schemathesis has been analyzed as a schema/property-based baseline.
* [ ] crAPI, WebGoat, and Juice Shop have been evaluated as laboratory/benchmark candidates.
* [ ] Every major research claim has supporting evidence.
* [ ] Existing capabilities and unknowns are explicitly separated.
* [ ] A non-overlap matrix has been completed.
* [ ] RQs are frozen.
* [ ] Phase 1 non-goals are frozen.
* [ ] Threat model is frozen.
* [ ] AI-use conditions are frozen.
* [ ] The final Phase 1 development boundary is approved by the supervisor.

The key milestone is therefore not simply **"finished reading the papers"**, but:

> **"The team can justify exactly what is already known, what existing tools already provide, what remains unresolved, and why the Phase 1 implementation is limited to the proposed stateful testing foundation."**
