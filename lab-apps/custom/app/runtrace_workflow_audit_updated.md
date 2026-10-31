# RunTrace workflow and traffic update

## What changed

- RunTrace now loads synthetic actor credentials from `cyber-range/model/rso.yaml` when environment variables are not supplied. Environment variables take precedence.
- Added `actor-supplier-b` to support cross-tenant invoice/payout read probes.
- Added response assertions to traffic steps: expected HTTP status and expected resource `State`/`Status`.
- Assertion results are written to the evidence JSON. Failed assertions cause CLI exit code 2; dry-run assertions are explicitly marked `skipped`, not passed.
- Gateway loads only the actor registry (`actors`) from RSO. It does not load `vulnerability_flags`, planted labels, or ground truth.
- Expanded read-only authorization traffic to cover same-tenant different-owner and cross-tenant supplier reads.
- RunTrace authenticates lab actors through `/__lab/auth/token`; the customer/supplier sign-in endpoints are separate base API operations.

## Current suite

- 6 scenarios
- 48 DSL steps
- 34 explicit `request` DSL steps and 14 `login` steps, for 48 HTTP calls total.
- All 34 explicit request method/path pairs and the token endpoint used by login are allowlisted.

## Workflow status contracts

| Workflow | State progression checked |
|---|---|
| Order refund | delivered -> return_pending -> returned |
| Ticket lifecycle | open -> assigned -> closed |
| Invoice payment | draft -> submitted -> approved -> paid |
| Payout release | pending -> approved -> released |
| Ticket escalation | open -> assigned -> escalated -> resolved |

The read-only authorization scenario checks expected HTTP status for own-object, cross-tenant, same-tenant/different-owner, and supplier invoice/payout reads.

## Execution

Dry-run validates routing and allowlist only; response/state assertions are skipped because no API response is received.

```bash
python runtrace.py --suite runtrace_traffic_suite.json
python runtrace.py --suite runtrace_traffic_suite.json --scenario-id workflow-invoice-payment --dry-run
python runtrace.py --suite runtrace_traffic_suite.json --scenario-id workflow-invoice-payment
```

Run each state-mutating workflow against a clean reset/reseed. The ticket lifecycle and ticket escalation scenarios both mutate `ticket-a-001`; never run them back-to-back without reset.

## Important limitations

- Live read-only `authorization-read-probes` run passed: 18 steps, 15 assertions, 0 failures/skips. Stateful mutation workflows were not run.
- Seed reset is an operator responsibility; RunTrace deliberately does not call admin reset automatically.
- Assertions verify response status and returned state/status. They do not independently query database state or prove audit-history completeness.
- The suite does not read `planted.csv` or vulnerability flags. Expected statuses are authored from the benign workflow and authorization policy, not discovered from hidden labels.
