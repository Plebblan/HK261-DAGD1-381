# RunTrace workflow capture

RunTrace now treats each use case as an ordered user journey, not a collection
of expected outcomes. The five baseline journeys are stored separately in
`cyber-range/traces/usecases/`: order refund, ticket lifecycle, invoice payment,
payout release, and ticket escalation.

Every step has an actor and interaction metadata: sequence number, conceptual
screen, user action, API operation ID, and object ID when applicable. The mock
range has no browser frontend, so screen/action labels identify the intended
use case location; they are not claimed to come from observed browser events.
RunTrace forwards these labels as capture headers, and the gateway writes them
into proxy events alongside method, path, request, response, and status.

Expected status/state fields were removed from the baseline journeys. The
captured response is evidence for later workflow reconstruction and review;
these scenarios do not score a security verdict. Older authorization probes
remain under `cyber-range/traces/probes/` and are distinct from baseline
workflow capture.

Run one journey at a time and reset/reseed before state-changing use cases.
Reset replaces all seeded collections, so use a disposable database.
