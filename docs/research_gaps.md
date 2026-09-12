# OVERVIEW

## Gap 1: State - Space Explosion in Multi - Actor Workflow

### Reason: 

* Interleaves Action: when there n possibles process for 1 actor then independent concurrent execution can result in up to nˆm global state with m is number of actor.
* Asynchorous Communication: message queue, delay, network latency can lead to vast permutations of of system history.
* Branch Decisions: interal logic of lots of actors who make their choices simultaneouslys can create multiply of total path combinations.
* Data-Dependent States: When the workflow state depends on variable data (dollar amounts, approval levels) passed between actors, the state space expands from discrete logical steps to infinite data combinations.

### Consequences:

* Verifiction Failure (False Positives & False Negatives): Lacking knowledge of complex multi-step prerequisite sequences. Unrecognize fuzzing mutates or deletes shared database properties across sessions, corrupting the runtime state and causing accuracy loss, false verdicts.
* Testing Gap: No model for state-aware plan can lead to most of generated request violate bussiness rules and trigger rejection immediately. That also mean trapping in shallow endpoint checks. Beside, scanner fails to map how state change executed by priviledged/unpriviledged role affect shared objects.
* Performance Dregadation: Explosion lead to exhaustion of computational budgets, CPU, network bandwidth without finding actionable process. Extreme latency and inf-loop traps extend test runs to hours or days, making CI/CD imcompatible.

## Gap 2: Semantic Inadequacy of Schema-based DAST & LLM Hallucination Risks)

### Reason:

* Structural and Semantic Boundary (OpenAPI Limitations): OpenAPI Specifications strictly define data types, payload structures, path formats, and query parameters. security semantics, fine-grained access policies, or business rules is hard to express, cause lack off methods.
* Object and Session Blindness: Schema definitions treat Object UUIDs or numerical IDs as generic primitive types. They are completely recognize object ownership, session boundaries, and tenant isolation rules across multi-role environments.
* Lack of Business Invariants: Schema-based treat endpoints as isolated, static functions. Completly ignore or can not model or track state transitions occurring across multi-step API workflows.

