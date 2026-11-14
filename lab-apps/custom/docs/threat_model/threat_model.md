# Summary
This is a Data flow and Threat/Safety model report for Custom App 1 - a vulnerable web application designed to educate about API security.
Uses STRIDE framework
# Asset Information
- **Name:** Custom App 1
- **Description:** This Custom App is an E-Commerce Marketplace application
- **Internet Facing:** Yes
- **Authentication Type:** PASSWORD
# Threat Model Inventory --- Inlanefreight E-Commerce Marketplace Mock API

## 1. Scope and assumptions
- **Application:** Inlanefreight E-Commerce Marketplace
- **API base URL in the contract:** `http://localhost:8000`
- **Implementation stack:** FastAPI with MongoDB persistence
- **Intended environment:** Local, authorized Cyber Range using synthetic accounts and data
- **Purpose of this inventory:** Identify external entities, major processes, and trust boundaries for a first-pass threat model.

> **Modeling note:** This is a logical application-level inventory, not
> a verified deployment/network diagram. Confirm actual deployment
> topology, runtime configuration, storage mounts, and operator access
> before treating the boundaries as deployment facts.

## 2. External entities

External entities are people, systems, or actors outside the process being modeled that interact with the application or its data.

| ID | External entity | Description and interaction |
| --- | --- | --- |
| E1 | Customer | Marketplace user who signs in and manages customer profile data, payment options, and orders. |
| E2 | Supplier | Marketplace supplier who manages supplier-related information, company information, products, discounts, and related documents/reports, subject to role and company-staff requirements. |
| E3 | Administrator | Privileged actor represented in the application's lab/admin workflows. Can perform administrative actions exposed by the lab implementation. |
| E4 | Support staff | Support-oriented actor/role represented in the lab actor model and associated workflows. |
| E5 | Anonymous user | Client that accesses public endpoints without an authenticated identity. Include this actor when assessing whether protected resources or operations are unintentionally accessible. |
| E6 | API client / frontend | Browser, frontend, script, or other HTTP client that sends requests to the API and receives responses. This is a technical caller rather than a business role. |

**Role distinction:** The implementation's lab actor model includes
customer, supplier, support, and admin roles. Do not assume that every
lab-only role or administrative capability is part of a separate
production marketplace deployment unless confirmed.

## 3. Processes

Processes represent application functions that receive input, perform
logic, access data, or return results. The endpoint groupings below are
logical threat-model processes; they are not necessarily separate
runtime services.

| ID | Process | Main responsibility / relevant API area |
| --- | --- | --- |
| P1 | Authentication management | Sign-in and authentication-related operations under `/api/v1/authentication/*`; establishes the caller identity/token context used by protected operations. |
| P2 | Authorization and access control | Checks whether the authenticated or anonymous caller may perform an operation, including role- and permission-based checks. |
| P3 | Customer management | Creates, reads, and updates customer-related information and current-user customer resources. |
| P4 | Supplier management | Manages supplier records and supplier-facing resources. |
| P5 | Supplier company management | Manages supplier-company information and company-scoped operations, including staff-related restrictions. |
| P6 | Product management | Manages marketplace product records and associated product information. |
| P7 | Product discount management | Manages discount-related resources and operations associated with products. |
| P8 | Customer payment management | Manages customer payment-option records. The presence of payment-option resources does **not** establish that the application integrates with an external payment processor. |
| P9 | Customer order management | Manages customer order records and order-related operations. |
| P10 | Order-item management | Manages items associated with orders and their related data. |
| P11 | File upload and retrieval | Accepts and serves uploaded documents/images, including product photos and certificates. The contract describes file storage; verify the actual runtime storage location and access controls. |
| P12 | Password-reset management | Password-reset functionality is described in the API contract. In the inspected implementation, the reset operation is not fully implemented and returns `501`; do not model an operational OTP email/SMS delivery integration as an existing process. |
| P13 | Database management | Reads and writes application records through the MongoDB client, using the configured MongoDB URI and database name. |
| P14 | Audit and request logging | Records request/audit information, including the implementation's audit-event handling. Consider the confidentiality and integrity of these records. |
| P15 | Lab resource management | Exposes lab-oriented resources and state used by the authorized Cyber Range exercises. |
| P16 | Business workflow management | Handles stateful marketplace/lab workflows involving resources such as orders, tickets, invoices, payouts, reviews, and related transitions. |
| P17 | Lab administration | Provides lab-specific status, reset, token, resource, and administrative-action functionality under the lab route namespace (including `/__lab/*`). |

### Important implementation/documentation differences

- The OpenAPI contract documents password-reset/OTP behavior, but the inspected implementation returns `501` for the password-reset operation. Treat the documented behavior as intended/contractual behavior, not as a currently functioning integration.
- Payment-option endpoints do not, by themselves, prove the existence of an external payment gateway.
- The OpenAPI contract describes file-upload behavior, including product-photo and certificate uploads. Confirm the actual storage path, filesystem permissions, retention, and serving mechanism in the deployment.
- Lab administration endpoints and lab actors are part of the local Cyber Range implementation. Keep them distinct from ordinary marketplace functionality in the diagram and risk assessment.

## 4. Trust boundaries

A trust boundary is a point where data or control crosses between
components or principals with different trust levels. These are logical
boundaries inferred from the implementation and API contract; validate
them against the actual deployment.

| ID | Trust boundary | What crosses the boundary | Security questions to assess |
| --- | --- | --- | --- |
| TB1 | Client--application boundary | HTTP requests, headers, tokens, query/path parameters, request bodies, and API responses between external clients and FastAPI. | Are inputs validated? Is transport protected in the deployed environment? Are errors and responses safe? |
| TB2 | Anonymous--authenticated boundary | Requests made without credentials versus requests carrying an authenticated identity/token. | Are protected routes consistently gated? Can identity be forged, reused, or confused? |
| TB3 | Role/permission boundary | Operations requested by customer, supplier, support, or admin actors with different permissions. | Are role and permission checks enforced server-side for every operation? |
| TB4 | Object-ownership boundary | Access to customer-, supplier-, company-, order-, and other object-specific identifiers and records. | Does the server verify that the caller is entitled to the specific object, not merely that the caller is authenticated? |
| TB5 | Tenant/company isolation boundary | Access across supplier companies or other logical ownership/grouping scopes. | Are company/tenant identifiers bound to the caller's authorized scope? Can one company access another company's data or mutate its records? |
| TB6 | Application--database boundary | Database queries and mutations between FastAPI and MongoDB. | Are database credentials and network access restricted? Are queries scoped to the caller's authorization context? Are secrets protected? |
| TB7 | Application--file-storage boundary | Uploaded file bytes, metadata, and file retrieval between the API and its configured storage. | Are file types, sizes, names, paths, access permissions, and download authorization controlled? Is retention intentional? |
| TB8 | Marketplace--lab-administration boundary | Requests and control actions directed at lab-only routes and administrative state. | Are lab controls isolated from normal user routes? Are reset/admin actions restricted to intended lab operators and conditions? |
| TB9 | Cyber Range--surrounding environment boundary | Test traffic, test data, and operator/orchestrator actions crossing between the local target and the wider host/network environment. | Is the target restricted to the authorized range? Are outbound connections controlled? Are synthetic data and test credentials used? |

## 5. Logical data-flow overview

``` mermaid
flowchart LR
    E1[Customer]
    E2[Supplier]
    E3[Administrator]
    E4[Support staff]
    E5[Anonymous user]
    E6[API client / frontend]

    subgraph TB1[TB1 — Client / application boundary]
        API[FastAPI application]
        AUTH[P1 Authentication]
        AUTHZ[P2 Authorization]
        BIZ[P3–P12 Marketplace processes]
        LAB[P15–P17 Lab processes]
        AUDIT[P14 Audit and request logging]
        FILES[(File storage)]
        DB[(MongoDB)]
    end

    E1 --> E6
    E2 --> E6
    E3 --> E6
    E4 --> E6
    E5 --> E6
    E6 --> API
    API --> AUTH
    AUTH --> AUTHZ
    AUTHZ --> BIZ
    AUTHZ --> LAB
    BIZ --> DB
    BIZ --> FILES
    LAB --> DB
    API --> AUDIT
```

The diagram is intentionally logical: it groups processes and shows the
major data stores. It does not assert that MongoDB or file storage is on
a separate host or network segment. Add explicit network/deployment
boundaries after checking the actual Docker, host, and storage
configuration.

## 6. Threat Table — Inlanefreight E-Commerce Marketplace Mock API

The table below follows the **Threat / STRIDE category / Attack Vector / Impact level / Risk rating / Affected components** format used in the crAPI report.

I’ve incorporated your business state graph as context enrichment, especially the order-return/refund, ticket, invoice, and payout workflows. One important distinction: the supplied FastAPI implementation contains a generic e-commerce API and a separate lab-resource workflow handler. The lab handler implements order and ticket actions, but I did not find corresponding invoice or payout transitions in that handler. Therefore, invoice and payout entries below are treated as modeled workflow risks to validate, not confirmed implementation flaws.

The ratings are preliminary threat-model judgments, not claims that every issue is currently exploitable. Several lab vulnerabilities are conditional on their `LAB_VULNERABILITIES` flags being enabled.

## Threat Table

| Threat | STRIDE category | Attack Vector | Impact level | Risk rating | Affected components |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Spoofing Customer or Supplier Identity** | SPOOFING | The local mock accepts bearer values in the `local:customer:<email>` and `local:supplier:<email>` formats and resolves the actor from the supplied email. Because these values are not signed or backed by a server-side session, a caller able to construct one may be able to impersonate a seeded customer or supplier. This behavior is specific to the local mock authentication design and should not be interpreted as the production authentication design. | HIGH | HIGH | Customer, Supplier, Authentication Process, Customer Management Process, Supplier Management Process, Internet Boundary |
| **Unauthorized Access to Role-Restricted Functions** | ELEVATION OF PRIVILEGE | The OpenAPI contract declares endpoint role requirements, but the generic dispatcher primarily checks whether a local actor is authenticated and has a customer or supplier role. It does not appear to enforce each operation’s `x-required-roles` permission list. A lower-privileged authenticated actor may therefore reach functions intended for a more privileged role if no additional control is applied. | HIGH | HIGH | Customer, Supplier, Admin, Authentication Process, Authorization Process, Product Management Process, Supplier Management Process, Supplier Company Management Process, Order Management Process, Service Authorization Boundary |
| **Accessing Another Customer’s or Supplier’s Object** | INFORMATION DISCLOSURE | A caller may attempt to retrieve or modify an object by supplying another object’s identifier. In the generic dispatcher, identifier-based queries are constructed from route parameters, while ownership checks are not consistently applied to every object operation. The lab-resource handler has explicit ownership checks and conditional test cases for same-tenant object access; those cases should be evaluated separately from the generic API routes. | HIGH | HIGH | Customer Management Process, Supplier Management Process, Product Management Process, Order Management Process, Order Item Management Process, Supplier Company Management Process, Database Management Process, Object Ownership Boundary |
| **Cross-Tenant Data Access** | INFORMATION DISCLOSURE | A user belonging to one tenant may attempt to retrieve resources or collection results belonging to another tenant by changing an object identifier or tenant filter. The lab-resource list handler includes tenant filtering, with a conditional cross-tenant test case. The tenant dimension must be checked for both individual resource reads and collection results; a successful response alone does not establish a leak. | HIGH | HIGH | Customer, Supplier, Support, Lab Resource Management Process, Customer Order Management Process, Ticket Management Process, Tenant Isolation Boundary |
| **Exposure of Unnecessary Object Properties** | INFORMATION DISCLOSURE | Read operations may return complete database records rather than a role-specific field set. The response serializer excludes a defined set of secret fields, but this does not by itself establish that all personal, commercial, financial, or internal properties are appropriate for every actor. Compare the returned fields with the field policy for the actor and object type. | HIGH | HIGH | Customer Database, Supplier Database, Customer Order Management Process, Product Management Process, Supplier Company Management Process, Database Management Process, Data Persistence Boundary |
| **Unauthorized Modification of Protected Object Properties** | TAMPERING | Generic `PUT` and `PATCH` handling applies request-body fields to stored records using a MongoDB `$set` operation. If an endpoint does not enforce a writable-field policy, a caller may attempt to change properties that should be server-controlled, such as ownership, supplier/customer association, status, or privileged flags. The lab-resource update handler has a narrower property allowlist, with additional conditional cases for protected-field changes. | HIGH | HIGH | Customer Management Process, Supplier Management Process, Product Management Process, Supplier Company Management Process, Order Management Process, Database Management Process, Object Ownership Boundary, Data Persistence Boundary |
| **Unauthorized Product or Company File Upload** | TAMPERING | Product-photo and certificate upload handlers select the target record using a supplied product or company identifier and store the uploaded content. The implementation should verify that the authenticated supplier owns or is authorized to manage the target product or company before updating the file field. A role check alone would not establish object ownership. | MEDIUM | HIGH | Supplier, Product Management Process, Supplier Company Management Process, File Upload and Retrieval Process, Database Management Process, Object Ownership Boundary |
| **Unauthorized Order Return or Refund** | TAMPERING | An actor may attempt to invoke a refund action without first satisfying the declared order workflow. The business graph requires `delivered` → `return_pending` → `returned`, restricts the return request to the owning Customer, and reserves refund approval for Admin. The lab transition handler also contains conditional refund cases and permits the refund action for customer or admin actors under its implemented conditions. This creates a validation point against the declared role and state rules, including whether a refund can be replayed or accepted from an invalid state. | CRITICAL | CRITICAL | Customer, Admin, Customer Order Management Process, Order Tracking Process, Business Workflow Management Process, Order Database, Service Authorization Boundary |
| **Replaying a Refund or Reversing a Terminal Order State** | TAMPERING | A caller may retry a refund action or attempt another transition after an order has reached `returned`. The graph declares `returned` terminal and requires a refund transition to occur at most once. The evaluator should compare the order state before and after repeated attempts and verify that a rejected attempt leaves the state unchanged. | CRITICAL | HIGH | Customer Order Management Process, Order Tracking Process, Business Workflow Management Process, Order Database, Data Persistence Boundary |
| **Unauthorized Ticket Assignment, Escalation, or Closure** | TAMPERING, ELEVATION OF PRIVILEGE | A caller may attempt to assign, escalate, resolve, or close a ticket without satisfying the required role, tenant relation, and preceding state. The graph restricts assignment, escalation, and closure to Support under the specified conditions, while resolution is reserved for Admin after escalation. The lab handler implements assignment and closure paths, but the supplied implementation does not show the full escalation/resolution sequence from the graph. | HIGH | HIGH | Support, Admin, Ticket Management Process, Business Workflow Management Process, Ticket Database, Tenant Isolation Boundary, Service Authorization Boundary |
| **Unauthorized Invoice Approval or Payment** | TAMPERING, ELEVATION OF PRIVILEGE | A Supplier may attempt to approve or pay an invoice, or submit a payment transition before approval. The graph requires `draft` → `submitted` → `approved` → `paid`, reserves approval and payment for Admin, and prohibits supplier self-approval. These transitions should be checked against the application’s runtime implementation; the supplied lab transition handler does not show invoice transition handling. | CRITICAL | HIGH | Supplier, Admin, Invoice Management Process, Business Workflow Management Process, Invoice Database, Service Authorization Boundary |
| **Unauthorized Payout Approval or Release** | TAMPERING, ELEVATION OF PRIVILEGE | A caller may attempt to release a payout while it is still `pending`, approve it without the required role, or repeat a release after the payout has reached its terminal state. The graph requires `pending` → `approved` → `released` and assigns both transitions to Admin. The supplied lab transition handler does not show payout transition handling, so these are workflow requirements to validate rather than confirmed implementation weaknesses. | CRITICAL | HIGH | Admin, Payout Management Process, Business Workflow Management Process, Payout Database, Service Authorization Boundary |
| **Unauthorized Access to Administrative Lab Actions** | ELEVATION OF PRIVILEGE | A non-admin actor may attempt to invoke administrative actions such as archive or export. The lab handler normally restricts these actions to Admin, but includes conditional vulnerability cases for selected actors when the corresponding lab flags are enabled. Tests should verify both the role decision and whether any protected state or operation changes after a denied attempt. | HIGH | HIGH | Customer, Support, Admin, Lab Administration Process, Authorization Process, Lab Resource Management Process, Service Authorization Boundary |
| **Unauthorized Deletion of Another Actor’s Resource** | TAMPERING | A caller may attempt to delete a resource that they do not own. The lab-resource delete handler checks ownership or Admin role, but contains a conditional test case that permits a specified customer to delete a selected resource when its vulnerability flag is enabled. A successful deletion outside the actor’s ownership or administrative scope would violate the object-access policy. | HIGH | HIGH | Customer, Admin, Lab Resource Management Process, Database Management Process, Object Ownership Boundary |
| **Denial of Service Through Unbounded API Requests** | DOS | Repeated requests to list, search, count, or retrieve resources may consume application or database capacity if request rates, query cost, pagination, and resource limits are not controlled. The generic dispatcher applies a fixed result limit to some collection reads, but this alone does not establish comprehensive rate limiting or protection against expensive request patterns. | MEDIUM | MEDIUM | API Client, Customer Management Process, Supplier Management Process, Product Management Process, Order Management Process, Database Management Process, Internet Boundary |

---

## Important Validation Notes

* **Order workflow:** The graph declares refund as an Admin action, but the lab transition handler allows both Customer and Admin actors into the refund branch under certain conditions. This is a direct mismatch worth testing against `ORDER-I01` to `ORDER-I03`.
* **Ticket workflow:** The graph includes escalation and resolution, but the lab handler shown implements assignment and closure only. Do not report missing escalation or resolution as an exploitable flaw until the intended runtime behavior is confirmed.
* **Invoice and payout workflows:** Their state machines are defined in your YAML, but I could not verify corresponding transition handlers in the supplied implementation. Keep these as requirements and validation targets for now.
* **Authorization:** The OpenAPI contract declares role requirements and object-ownership expectations. The generic dispatcher’s visible authorization logic does not consistently demonstrate enforcement of those requirements, so runtime checks are important.
* **Authentication:** The source explicitly describes this as a local development mock, not a production authentication server. The local bearer-token format should therefore be documented as a mock-environment limitation, not attributed to a production deployment.

---

## Mapping to Authorization and Business-Logic Taxonomy

| Taxonomy family | Corresponding threats in the table |
| :--- | :--- |
| **F1 — BOLA / IDOR** | Accessing another customer’s or supplier’s object |
| **F2 — BFLA** | Unauthorized access to role-restricted functions; unauthorized administrative lab actions |
| **F3 — BOPLA** | Exposure of unnecessary object properties; unauthorized modification of protected object properties |
| **F4 — Tenant isolation breakage** | Cross-tenant data access |
| **F5 — Bounded workflow abuse** | Unauthorized order return/refund; refund replay; ticket transition violations; unauthorized invoice or payout transitions |

## 6. Suggested first-pass threat-model checklist

- [ ] Confirm which routes are public, authenticated, and role-restricted.
- [ ] Define the expected permissions for customer, supplier, support, admin, and anonymous actors.
- [ ] Identify ownership rules for customer, supplier, company, order, and file objects.
- [ ] Identify tenant/company scoping rules and the identifiers used to enforce them.
- [ ] Document the state machines and permitted transitions for orders, tickets, invoices, payouts, and other workflow resources.
- [ ] Confirm MongoDB deployment location, credentials, network exposure, and database-level permissions.
- [ ] Confirm file-storage location, access controls, filename/path handling, and retention.
- [ ] Verify that lab reset and administrative controls cannot be reached or exercised outside the intended Cyber Range context.
- [ ] Separate implemented behavior from OpenAPI-described but unimplemented behavior (notably password reset).
- [ ] Confirm whether any external services (email, SMS, payment processor, identity provider, object storage) are actually configured before adding them as external entities.

## 7. Source basis

- **Application implementation:** `Pasted text.txt` --- FastAPI/MongoDB implementation (`main.py`).
- **OpenAPI contract:** `Pasted text (2).txt` --- OpenAPI 3.0 contract for the E-Commerce Marketplace API.
- **Supporting project context:** Uploaded project description PDF and `families.yaml` taxonomy were not used to invent application components; this inventory is focused on the app implementation and its API contract.
