# RQ1: Automatic Synthesis of Role–Session–Object Topologies and Business State Graphs

## Research Question 1

**RQ1:** How can Role–Session–Object topologies and Business State Graphs be automatically synthesized from OpenAPI specifications and passive traffic captures?

The proposed approach is to combine two complementary sources of evidence:

- **OpenAPI specifications** provide the static API structure: operations, parameters, schemas, resources, identifiers, and security requirements.
- **Passive HTTP traffic** provides evidence of actual API usage: identities, sessions, object identifiers, request ordering, and observable state changes.

The synthesis process is could therefor be:

```text
OpenAPI specification
        |
        v
Operation / Resource Model
        |
        +-------------------+
                            |
Passive HTTP Traffic        |
        |                   |
        v                   v
Trace / Identity / Object Analysis
        |
        v
Role–Session–Object Topology
        |
        v
State Transition Inference
        |
        v
Business State Graph
```

## 1. Extract API and Resource Dependencies from OpenAPI

The OpenAPI specification is parsed to extract HTTP methods, paths, parameters, request/response schemas, resource identifiers, operation IDs, and security requirements.

These elements can be represented as an operation/resource graph:

\[
G_A=(O,R,E)
\]

where $O$ represents operations, $R$ resources, and $E$ relationships between them.

A key relationship is the producer–consumer dependency:

```text
POST /orders
      |
      | produces order.id
      v
GET /orders/{id}
      |
      | consumes order.id
```

RESTler automatically extracts such producer–consumer dependencies from Swagger/OpenAPI specifications and uses them to construct stateful request sequences [1]. Resource- and dependency-based REST testing similarly uses resource relationships for test generation [2].

Thus, OpenAPI provides the **initial structural model** of operations and resources.

## 2. Reconstruct Interaction Traces from Passive Traffic

Passive HTTP captures provide concrete executions that are not necessarily represented completely in OpenAPI.

Each interaction can be represented as:

\[
e_i=(t_i,id_i,req_i,resp_i)
\]

where $t_i$ is the timestamp, $id_i$ is observable identity information, and $req_i$ and $resp_i$ are the request and response.

Related events can then be grouped into traces:

\[
Trace_s=\langle e_1,e_2,\ldots,e_n\rangle
\]

Possible session signals include cookies, session identifiers, JWT subject claims, authentication tokens, client context, and temporal ordering.

For example:

```text
Identity: User A
Session: S1

POST /orders
GET /orders/827
POST /orders/827/payment
```

The traffic therefore provides **observed execution evidence**, rather than only the structural possibilities described by OpenAPI.

## 3. Correlate OpenAPI Operations with Traffic

Each observed request is mapped to its corresponding OpenAPI operation:

```text
Traffic                    OpenAPI

POST /orders        --->   POST /orders
GET /orders/827     --->   GET /orders/{id}
POST /orders/827/payment
                    --->   POST /orders/{id}/payment
```

The two sources can then be correlated through parameters and resource identifiers. For example, OpenAPI may indicate that `POST /orders` produces an `Order.id` consumed by `GET /orders/{id}`, while traffic shows:

```text
POST /orders
    response: {"id": 827}

GET /orders/827
```

The matching identifier provides evidence that both operations concern the same object.

## 4. Construct the Role–Session–Object Topology

The reconstructed observations can be represented as:

\[
e_i=(r_i,s_i,o_i,a_i)
\]

where $r_i$ is an actor or candidate role, $s_i$ is a session, $o_i$ is an object, and $a_i$ is an API operation.

The resulting topology is:

\[
G_{RSO}=(V,E)
\]

For example:

```text
Customer
    |
    | uses
    v
 Session S1
    |
    | performs
    v
POST /orders
    |
    | creates
    v
Order#827
    |
    +---- GET /orders/827
    |
    +---- POST /orders/827/payment
```

Object links can be inferred by correlating identifiers appearing in request paths, request bodies, response bodies, and OpenAPI schemas.

## 5.