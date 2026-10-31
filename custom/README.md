# Inlanefreight API mock backend

MongoDB-backed backend for locally exercising the endpoints in `docs/app1/openapi.json`.
It is a mock implementation: it accepts the contract's routes and common JSON CRUD flows,
but does not reproduce the original service's business rules or authentication.

## Run with Docker

```sh
docker compose up --build
```

- Swagger UI: <http://localhost:8000/docs>
- API health: <http://localhost:8000/health>
- MongoDB: `mongodb://localhost:27017` (database `inlanefreight_api`)

Example:

```sh
curl -X POST http://localhost:8000/api/v1/customers \
  -H 'Content-Type: application/json' \
  -d '{"NewCustomer":{"Name":"Demo Customer","Email":"demo@example.test","PhoneNumber":"0900000000","BirthDate":"2000-01-01","Password":"demo"}}'
curl http://localhost:8000/api/v1/customers
```

Demo data and sign-in accounts are loaded automatically from `app/seed.py`. See [BACKEND_API.md](BACKEND_API.md) for the seed accounts and route examples. Data persists in the `mongo_data` Docker volume.
To clear the local test database, run `docker compose down -v`.

## Custom Cyber Range apps (TenantDesk and ShopFlow)

Two self-contained, in-memory FastAPI apps live in `app/custom/` (no MongoDB needed). Each planted flaw is a named switch.

```sh
docker compose --profile custom up --build tenantdesk shopflow
```

| App | URL | Flaws | Accounts (password `pw-<username>`) |
| --- | --- | --- | --- |
| TenantDesk | <http://localhost:8001/docs> | `TD-01`..`TD-17` | alice, adam, amy, ann (acme); gina, greg, gus (globex) |
| ShopFlow | <http://localhost:8002/docs> | `SF-01`..`SF-14` | olga, sam, cathy, carl (acme-shop); greta, steve, chris (globex-shop) |

- Choose flaws with `TD_ENABLED_FLAWS` / `SF_ENABLED_FLAWS`: `ALL` (default), `NONE` (patched twin) or a list such as `TD-01,TD-04`.
- Control plane (header `X-Lab-Key`, default `lab-only-synthetic-key`): `POST /_lab/reset`, `GET /_lab/state`, `GET /_lab/audit`, `GET /_lab/health`. Reset before every case, because cases share mutable seed state.
- Ground truth: `cyber-range/ground_truth/planted_cases_custom.csv` and `cyber-range/schema/ground_truth.json`; model, workflows and seed objects are the `*_custom` files under `cyber-range/`. Cases AUTHZ-113, AUTHZ-207 and AUTHZ-211 need setup steps, listed in `seed/objects_custom.json`.
- Checks: `python cyber-range/validate_custom.py` (stdlib only) verifies that the artifacts, code and OpenAPI docs agree; `pytest tests` replays every planted and benign case (needs `pip install pytest httpx`).

