"""MongoDB-backed local mock API generated from the repository OpenAPI contract.

This is a development Cyber Range target, not a production authentication server.
All test traffic should be restricted to this local service. The tester/orchestrator
must implement its own outbound Safety Gateway; this file records target-side evidence.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from bson import ObjectId
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pymongo import MongoClient
from pymongo.errors import PyMongoError

from app.seed import reset_database, seed_database

# Support either common project layout: repo/openapi.json + repo/app/main.py,
# or repo/app/main.py + repo/app/openapi.json.
_CANDIDATE_SPECS = [
    Path(__file__).resolve().parents[1] / "openapi.json",
    Path(__file__).resolve().parent / "openapi.json",
]
SPEC_PATH = next((p for p in _CANDIDATE_SPECS if p.is_file()), None)
if SPEC_PATH is None:
    raise FileNotFoundError("openapi.json was not found beside the app package or at its parent")
SPEC: dict[str, Any] = json.loads(SPEC_PATH.read_text(encoding="utf-8"))

mongo = MongoClient(
    os.getenv("MONGODB_URI", "mongodb://localhost:27017"),
    serverSelectionTimeoutMS=3000,
)
db = mongo[os.getenv("MONGODB_DATABASE", "inlanefreight_api")]
app = FastAPI(title="Inlanefreight API Mock", version="1.1.0", docs_url="/docs")

SAFE_METHODS = {"get", "post", "put", "patch", "delete"}
SECRET_FIELDS = {"_id", "Password", "password", "CVV", "cvv", "AccessToken", "RefreshToken", "Token", "Secret"}


def source_openapi() -> dict[str, Any]:
    """Return a copy so we never mutate the loaded source contract."""
    spec = json.loads(json.dumps(SPEC))
    spec["servers"] = [{"url": os.getenv("PUBLIC_API_URL", "http://localhost:8000"),
                         "description": "Local development backend"}]
    bearer = [{"JWTBearerAuth": []}]
    ok = {"200": {"description": "Lab operation completed", "content": {"application/json": {"schema": {"type": "object"}}}}}
    spec.setdefault("paths", {}).update({
        "/__lab/auth/token": {"post": {"summary": "Issue a synthetic token for a seeded lab actor", "tags": ["Cyber Range"],
            "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "required": ["Email", "Password"], "properties": {"Email": {"type": "string"}, "Password": {"type": "string"}}}}}},
            "responses": ok}},
        "/lab/v1/resources": {"get": {"summary": "List resources visible to the current lab actor", "tags": ["Cyber Range"], "security": bearer,
            "parameters": [{"name": "resource_type", "in": "query", "schema": {"type": "string"}}, {"name": "q", "in": "query", "schema": {"type": "string"}}, {"name": "tenant_id", "in": "query", "schema": {"type": "string"}}], "responses": ok}},
        "/lab/v1/resources/{resource_id}": {
            "parameters": [{"name": "resource_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "get": {"summary": "Read an owned lab resource", "tags": ["Cyber Range"], "security": bearer, "responses": ok},
            "patch": {"summary": "Update allowed resource properties", "tags": ["Cyber Range"], "security": bearer,
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}}, "responses": ok},
            "delete": {"summary": "Delete an owned lab resource", "tags": ["Cyber Range"], "security": bearer, "responses": ok}},
        "/lab/v1/resources/{resource_id}/actions/{action}": {"parameters": [
            {"name": "resource_id", "in": "path", "required": True, "schema": {"type": "string"}},
            {"name": "action", "in": "path", "required": True, "schema": {"type": "string"}}],
            "post": {"summary": "Execute a modeled workflow transition", "tags": ["Cyber Range"], "security": bearer, "responses": ok}},
        "/lab/v1/admin/actions/{action}": {"parameters": [{"name": "action", "in": "path", "required": True, "schema": {"type": "string"}}],
            "post": {"summary": "Execute a role-restricted lab action", "tags": ["Cyber Range"], "security": bearer, "responses": ok}},
    })
    return spec


app.openapi = source_openapi  # type: ignore[method-assign]


@app.middleware("http")
async def hash_incoming_request(request: Request, call_next):
    raw_body = await request.body()
    request.state.request_raw_hash = hashlib.sha256(raw_body).hexdigest()
    if not request.headers.get("x-request-id"):
        request.state.request_id = str(uuid.uuid4())
    else:
        request.state.request_id = request.headers["x-request-id"]
    return await call_next(request)


@app.on_event("startup")
def load_development_seed() -> None:
    if os.getenv("SEED_DEMO_DATA", "true").lower() in {"1", "true", "yes"}:
        seed_database(db)


def jsonable(value: Any, *, include_token: bool = False) -> Any:
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, dict):
        excluded = SECRET_FIELDS - ({"Token"} if include_token else set())
        return {k: jsonable(v, include_token=include_token) for k, v in value.items() if k not in excluded}
    if isinstance(value, list):
        return [jsonable(v, include_token=include_token) for v in value]
    return value


def compile_path(template: str) -> tuple[re.Pattern[str], list[str]]:
    names: list[str] = []
    chunks: list[str] = []
    for part in template.strip("/").split("/"):
        if part.startswith("{") and part.endswith("}"):
            names.append(part[1:-1])
            chunks.append(r"([^/]+)")
        else:
            chunks.append(re.escape(part))
    return re.compile(r"^/" + "/".join(chunks) + r"/?$"), names


# Prefer static paths before parameterized paths (e.g. /current-user before /{ID}).
ROUTES: list[tuple[re.Pattern[str], list[str], str, dict[str, Any]]] = []
for route, operations in SPEC.get("paths", {}).items():
    pattern, names = compile_path(route)
    ROUTES.append((pattern, names, route, operations))
ROUTES.sort(key=lambda item: (item[0].pattern.count("([^/]+)"), -len(item[2])))


def collection_for(route: str) -> str:
    parts = route.strip("/").split("/")[2:]  # remove api/v1
    joined = "/".join(parts)
    if "yearly-reports" in joined:
        return "supplier_company_yearly_reports"
    if "quarterly-reports" in joined:
        return "supplier_quarterly_reports"
    if "payment-options" in joined:
        return "customer_payment_options"
    if "billing-addresses" in joined:
        return "customer_billing_addresses"
    if "orders" in joined and "items" in joined:
        return "customer_order_items"
    if "orders" in joined:
        return "customer_orders"
    if "discounts" in joined:
        return "product_discounts"
    if parts and parts[0] in {"supplier-companies", "suppliers", "products", "customers"}:
        return parts[0].replace("-", "_")
    return "misc"


def body_record(body: Any) -> dict[str, Any]:
    """Unwrap OpenAPI command DTOs (NewProduct, UpdatedProduct, etc.)."""
    if not isinstance(body, dict):
        return {"value": body}
    # Prefer a single nested object rather than hard-coding only New*/Updated*.
    nested = [v for v in body.values() if isinstance(v, dict)]
    if len(nested) == 1:
        return dict(nested[0])
    for key, value in body.items():
        if key.startswith(("New", "Updated", "Create", "Update")) and isinstance(value, dict):
            return dict(value)
    return dict(body)


def local_user_from_request(request: Request) -> dict[str, Any] | None:
    """Resolve only tokens issued by this mock sign-in endpoint."""
    auth = request.headers.get("authorization", "")
    lab_match = re.fullmatch(r"Bearer\s+lab\.([A-Za-z0-9_-]{32,})", auth, re.I)
    if lab_match:
        token_hash = hashlib.sha256(lab_match.group(1).encode()).hexdigest()
        session = db["lab_sessions"].find_one({"TokenHash": token_hash, "Active": True, "ExpiresAt": {"$gt": datetime.now(timezone.utc)}})
        if not session:
            return None
        user = db["lab_actors"].find_one({"ID": session.get("ActorID"), "Active": True})
        if not user:
            return None
        return {**user, "_mock_role": str(user.get("Role", "")).lower(), "_session_id": session.get("ID")}
    match = re.fullmatch(r"Bearer\s+local:(customer|supplier):([^\s:]+(?:@[^\s]+)?)", auth, re.I)
    if not match:
        return None
    role, email = match.group(1).lower(), match.group(2)
    collection = {"customer": "customers", "supplier": "suppliers", "lab": "lab_actors"}[role]
    user = db[collection].find_one({"Email": email})
    if not user:
        return None
    return {**user, "_mock_role": str(user.get("Role", role)).lower() if role == "lab" else role}


def audit(request: Request, template: str, status: int, actor: dict[str, Any] | None,
          evidence: dict[str, Any] | None = None) -> None:
    """Store minimal provenance for reproducible local tests; never store credentials."""
    if os.getenv("AUDIT_LOG_ENABLED", "true").lower() not in {"1", "true", "yes"}:
        return
    try:
        db["http_audit_events"].insert_one({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": request.method.upper(),
            "path": request.url.path,
            "operation_template": template,
            "status_code": status,
            "actor_id": actor.get("ID") if actor else None,
            "actor_role": actor.get("_mock_role") if actor else None,
            "request_id": getattr(request.state, "request_id", request.headers.get("x-request-id", str(uuid.uuid4()))),
            "run_id": request.headers.get("x-lab-run-id"),
            "sequence_id": request.headers.get("x-lab-sequence-id"),
            "step_idx": request.headers.get("x-lab-step-index"),
            "seed": request.headers.get("x-lab-seed"),
            "valid_request": request.headers.get("x-lab-valid-request"),
            "before_state_hash": hashlib.sha256(json.dumps((evidence or {}).get("state_before"), sort_keys=True, default=str).encode()).hexdigest() if (evidence or {}).get("state_before") is not None else None,
            "after_state_hash": hashlib.sha256(json.dumps((evidence or {}).get("state_after"), sort_keys=True, default=str).encode()).hexdigest() if (evidence or {}).get("state_after") is not None else None,
            "evidence": evidence or {},
        })
    except PyMongoError:
        # Audit database failure must not mask the API response in this mock.
        pass


def response(request: Request, template: str, payload: Any, status: int = 200,
             actor: dict[str, Any] | None = None,
             evidence: dict[str, Any] | None = None,
             expose_token: bool = False) -> JSONResponse:
    safe_payload = jsonable(payload)
    outgoing_payload = jsonable(payload, include_token=expose_token)
    response_hash = hashlib.sha256(json.dumps(safe_payload, sort_keys=True, default=str).encode()).hexdigest()
    provenance = {
        "request_raw_hash": getattr(request.state, "request_raw_hash", None),
        "response_raw_hash": response_hash,
        "case_id": request.headers.get("x-lab-case-id"),
        **(evidence or {}),
    }
    audit(request, template, status, actor, provenance)
    return JSONResponse(status_code=status, content=outgoing_payload)


def id_query(identifier: str, *, numeric: bool = False) -> dict[str, Any]:
    value: Any = int(identifier) if numeric and identifier.isdigit() else identifier
    # MongoDB's $or keeps UUID string IDs and numeric report IDs supported.
    return {"$or": [{"ID": value}, {"_id": identifier}]}


def operation_scopes(operation: dict[str, Any]) -> list[str]:
    security = operation.get("security", SPEC.get("security", []))
    scopes: list[str] = []
    for requirement in security or []:
        for scheme_scopes in requirement.values():
            if isinstance(scheme_scopes, list):
                scopes.extend(str(scope) for scope in scheme_scopes)
    return scopes


@app.get("/health")
def health() -> JSONResponse:
    try:
        mongo.admin.command("ping")
        return JSONResponse({"status": "ok", "database": "connected"})
    except PyMongoError as exc:
        return JSONResponse(status_code=503, content={"status": "error", "detail": str(exc)})


@app.get("/openapi-source.json", include_in_schema=False)
def openapi_source() -> JSONResponse:
    return JSONResponse(source_openapi())


def _lab_admin_authorized(request: Request) -> bool:
    """Require explicit lab mode, a configured secret, and a local client."""
    if os.getenv("LAB_MODE", "false").lower() not in {"1", "true", "yes"}:
        return False
    expected = os.getenv("LAB_ADMIN_TOKEN", "")
    if not expected:
        return False
    supplied = request.headers.get("x-lab-admin-token", "")
    if not secrets.compare_digest(supplied, expected):
        return False
    client_host = request.client.host if request.client else ""
    if client_host in {"localhost", "testclient"}:
        return True
    try:
        return ipaddress.ip_address(client_host).is_loopback or ipaddress.ip_address(client_host).is_private
    except ValueError:
        return False


@app.get("/__lab/status", include_in_schema=False)
def lab_status() -> JSONResponse:
    """Expose aggregate readiness only; never expose ground-truth labels."""
    try:
        mongo.admin.command("ping")
        seeded = db["lab_ground_truth"].count_documents({})
        return JSONResponse({"status": "ok", "lab_mode": os.getenv("LAB_MODE", "false").lower() in {"1", "true", "yes"},
                             "ground_truth_case_count": seeded,
                             "ground_truth_details_exposed": False})
    except PyMongoError:
        return JSONResponse(status_code=503, content={"status": "error", "database": "unavailable"})


@app.post("/__lab/reset", include_in_schema=False)
def lab_reset(request: Request) -> JSONResponse:
    """Reset deterministic lab data; disabled unless explicitly configured."""
    if not _lab_admin_authorized(request):
        return JSONResponse(status_code=403, content={"ErrorMessage": "Lab reset is disabled or unauthorized"})
    try:
        result = reset_database(db)
        return JSONResponse({"status": "reset", **result})
    except PyMongoError:
        return JSONResponse(status_code=503, content={"ErrorMessage": "Database reset failed"})


def lab_vulnerability_enabled(flag: str) -> bool:
    enabled = {item.strip() for item in os.getenv("LAB_VULNERABILITIES", "").split(",") if item.strip()}
    return "*" in enabled or flag in enabled


def lab_actor(request: Request) -> dict[str, Any] | None:
    actor = local_user_from_request(request)
    # dòng 318
    return actor if actor and actor.get("_mock_role") in {"customer", "support", "admin", "supplier"} else None

def lab_is_owner(actor: dict[str, Any], resource: dict[str, Any]) -> bool:
    return resource.get("OwnerID") == actor.get("ID")


def lab_can_read(actor: dict[str, Any], resource: dict[str, Any]) -> bool:
    role = actor.get("_mock_role")
    if role == "admin" or lab_is_owner(actor, resource):
        return True
    return role == "support" and resource.get("ResourceType") == "ticket" and resource.get("TenantID") == actor.get("TenantID")


def lab_case_actor(actor: dict[str, Any], expected_actor: str) -> bool:
    return actor.get("ID") == expected_actor


@app.post("/__lab/auth/token", include_in_schema=False)
async def lab_issue_token(request: Request) -> JSONResponse:
    """Issue a synthetic per-actor token for controlled local tests."""
    try:
        body = await request.json()
    except (ValueError, json.JSONDecodeError):
        body = {}
    actor = db["lab_actors"].find_one({"Email": body.get("Email"), "Password": body.get("Password"), "Active": True})
    if not actor:
        return response(request, "/__lab/auth/token", {"ErrorMessage": "Invalid lab credentials"}, 401)
    token_secret = secrets.token_urlsafe(36)
    token = f"lab.{token_secret}"
    now = datetime.now(timezone.utc)
    db["lab_sessions"].delete_many({"ExpiresAt": {"$lte": now}})
    db["lab_sessions"].insert_one({
        "ID": str(uuid.uuid4()),
        "ActorID": actor["ID"],
        "TokenHash": hashlib.sha256(token_secret.encode()).hexdigest(),
        "CreatedAt": now,
        "ExpiresAt": now + timedelta(hours=8),
        "Active": True,
    })
    return response(request, "/__lab/auth/token", {"Token": token, "TokenType": "Bearer", "ActorID": actor["ID"], "Role": actor["Role"], "TenantID": actor["TenantID"]}, 200, {**actor, "_mock_role": actor["Role"].lower()}, expose_token=True)


@app.get("/lab/v1/resources", include_in_schema=False)
def lab_list_resources(request: Request, resource_type: str | None = None, q: str | None = None) -> JSONResponse:
    actor = lab_actor(request)
    if not actor:
        return response(request, "/lab/v1/resources", {"ErrorMessage": "Valid lab bearer token required"}, 401)
    query: dict[str, Any] = {}
    if resource_type:
        query["ResourceType"] = resource_type
    docs = list(db["lab_resources"].find(query).limit(500))
    role = actor.get("_mock_role")
    visible = []
    leak_all = lab_vulnerability_enabled("AUTHZ-011") and lab_case_actor(actor, "actor-customer-a")
    leak_orders = lab_vulnerability_enabled("AUTHZ-019") and lab_case_actor(actor, "actor-customer-a")
    cross_tenant_search = lab_vulnerability_enabled("AUTHZ-012") and lab_case_actor(actor, "actor-customer-a")
    requested_tenant = request.query_params.get("tenant_id")
    for doc in docs:
        if q:
            searchable = json.dumps(doc.get("Properties", {}), ensure_ascii=False).lower()
            if q.lower() not in searchable:
                continue
        allowed = role == "admin" or doc.get("TenantID") == actor.get("TenantID") and (role == "support" or lab_is_owner(actor, doc))
        if requested_tenant and requested_tenant != actor.get("TenantID"):
            allowed = cross_tenant_search and doc.get("TenantID") == requested_tenant
        if leak_all or (leak_orders and doc.get("ResourceType") == "order"):
            allowed = True
        if allowed:
            visible.append(doc)
    return response(request, "/lab/v1/resources", visible, 200, actor,
                    {"actor_tenant": actor.get("TenantID"), "returned_resource_ids": [d.get("ID") for d in visible]})


@app.get("/lab/v1/resources/{resource_id}", include_in_schema=False)
def lab_get_resource(resource_id: str, request: Request) -> JSONResponse:
    actor = lab_actor(request)
    if not actor:
        return response(request, "/lab/v1/resources/{resource_id}", {"ErrorMessage": "Valid lab bearer token required"}, 401)
    resource = db["lab_resources"].find_one({"ID": resource_id})
    if not resource:
        return response(request, "/lab/v1/resources/{resource_id}", {"ErrorMessage": "Resource not found"}, 404, actor)
    per_object_cases = {
        "doc-b-001": ("AUTHZ-001", "actor-customer-a"),
        "order-a-001": ("AUTHZ-002", "actor-customer-b"),
        "ticket-a-001": ("AUTHZ-003", "actor-customer-b"),
        "doc-a-002": ("AUTHZ-004", "actor-customer-a"),
        "attachment-b-001": ("AUTHZ-016", "actor-customer-a"),
    }
    case = per_object_cases.get(resource_id)
    vulnerable = bool(case and lab_vulnerability_enabled(case[0]) and lab_case_actor(actor, case[1]))
    if not lab_can_read(actor, resource) and not vulnerable:
        return response(request, "/lab/v1/resources/{resource_id}", {"ErrorMessage": "Forbidden"}, 403, actor,
                        {"resource_id": resource_id, "owner_id": resource.get("OwnerID"), "tenant_id": resource.get("TenantID")})
    return response(request, "/lab/v1/resources/{resource_id}", resource, 200, actor,
                    {"resource_id": resource_id, "owner_id": resource.get("OwnerID"), "tenant_id": resource.get("TenantID"), "vulnerability_flag": case[0] if vulnerable else None})


@app.patch("/lab/v1/resources/{resource_id}", include_in_schema=False)
async def lab_update_resource(resource_id: str, request: Request) -> JSONResponse:
    actor = lab_actor(request)
    if not actor:
        return response(request, "/lab/v1/resources/{resource_id}", {"ErrorMessage": "Valid lab bearer token required"}, 401)
    resource = db["lab_resources"].find_one({"ID": resource_id})
    if not resource:
        return response(request, "/lab/v1/resources/{resource_id}", {"ErrorMessage": "Resource not found"}, 404, actor)
    try:
        changes = await request.json()
    except (ValueError, json.JSONDecodeError):
        changes = {}
    if not isinstance(changes, dict):
        return response(request, "/lab/v1/resources/{resource_id}", {"ErrorMessage": "JSON object required"}, 400, actor)
    owner = lab_is_owner(actor, resource)
    role = actor.get("_mock_role")
    # Safe baseline only permits a small set of user-editable presentation fields.
    allowed_properties = {"title", "subject", "priority"}
    prop_changes = changes.get("Properties", {})
    if not isinstance(prop_changes, dict):
        return response(request, "/lab/v1/resources/{resource_id}", {"ErrorMessage": "Properties must be an object"}, 400, actor)
    forbidden = set(changes) - {"Properties"}
    forbidden_properties = set(prop_changes) - allowed_properties
    vulnerable_flags: list[str] = []
    attacker_cases = [
        ("AUTHZ-008", "actor-customer-a", resource_id == "doc-a-001" and "OwnerID" in changes),
        ("AUTHZ-009", "actor-customer-a", resource_id == "doc-a-001" and "TenantID" in changes),
        ("AUTHZ-010", "actor-customer-a", resource_id == "order-a-001" and "refund_status" in prop_changes),
        ("AUTHZ-017", "actor-support-a", resource_id == "doc-a-001" and "is_privileged" in prop_changes),
        ("AUTHZ-018", "actor-customer-a", resource_id == "doc-a-001" and "is_privileged" in prop_changes),
    ]
    for flag, attacker, condition in attacker_cases:
        if condition and lab_vulnerability_enabled(flag) and lab_case_actor(actor, attacker):
            vulnerable_flags.append(flag)
    privileged_attempt = bool(forbidden or forbidden_properties)
    can_edit = owner or (role == "support" and resource.get("ResourceType") == "ticket" and resource.get("TenantID") == actor.get("TenantID")) or role == "admin"
    if (not can_edit and not vulnerable_flags) or (privileged_attempt and not vulnerable_flags and role != "admin"):
        return response(request, "/lab/v1/resources/{resource_id}", {"ErrorMessage": "Forbidden property or resource"}, 403 if not can_edit else 400, actor,
                        {"resource_id": resource_id, "state_before": resource.get("State")})
    update: dict[str, Any] = {}
    if "Properties" in changes:
        update["Properties"] = {**resource.get("Properties", {}), **prop_changes}
    for key in ("OwnerID", "TenantID"):
        if key in changes and (vulnerable_flags or role == "admin"):
            update[key] = changes[key]
    before = resource.get("State")
    if update:
        db["lab_resources"].update_one({"ID": resource_id}, {"$set": update})
    after_resource = db["lab_resources"].find_one({"ID": resource_id}) or resource
    return response(request, "/lab/v1/resources/{resource_id}", {"SuccessStatus": bool(update), "Resource": after_resource}, 200, actor,
                    {"resource_id": resource_id, "state_before": before, "state_after": after_resource.get("State"), "changed_fields": list(update), "vulnerability_flags": vulnerable_flags})


@app.delete("/lab/v1/resources/{resource_id}", include_in_schema=False)
def lab_delete_resource(resource_id: str, request: Request) -> JSONResponse:
    actor = lab_actor(request)
    if not actor:
        return response(request, "/lab/v1/resources/{resource_id}", {"ErrorMessage": "Valid lab bearer token required"}, 401)
    resource = db["lab_resources"].find_one({"ID": resource_id})
    if not resource:
        return response(request, "/lab/v1/resources/{resource_id}", {"ErrorMessage": "Resource not found"}, 404, actor)
    vulnerable = resource_id == "doc-b-001" and lab_vulnerability_enabled("AUTHZ-007") and lab_case_actor(actor, "actor-customer-a")
    if not (lab_is_owner(actor, resource) or actor.get("_mock_role") == "admin" or vulnerable):
        return response(request, "/lab/v1/resources/{resource_id}", {"ErrorMessage": "Forbidden"}, 403, actor)
    db["lab_resources"].delete_one({"ID": resource_id})
    return response(request, "/lab/v1/resources/{resource_id}", {"SuccessStatus": True}, 200, actor,
                    {"resource_id": resource_id, "deleted": True, "vulnerability_flag": "AUTHZ-007" if vulnerable else None})


@app.post("/lab/v1/admin/actions/{action}", include_in_schema=False)
def lab_admin_action(action: str, request: Request) -> JSONResponse:
    actor = lab_actor(request)
    if not actor:
        return response(request, "/lab/v1/admin/actions/{action}", {"ErrorMessage": "Valid lab bearer token required"}, 401)
    flag_for_action = {"archive": "AUTHZ-005", "export": "AUTHZ-006"}
    allowed = actor.get("_mock_role") == "admin"
    flag = flag_for_action.get(action)
    if flag and lab_vulnerability_enabled(flag):
        allowed = allowed or (action == "archive" and lab_case_actor(actor, "actor-customer-a")) or (action == "export" and lab_case_actor(actor, "actor-support-a"))
    if not allowed:
        return response(request, "/lab/v1/admin/actions/{action}", {"ErrorMessage": "Forbidden"}, 403, actor)
    return response(request, "/lab/v1/admin/actions/{action}", {"SuccessStatus": True, "Action": action}, 200, actor,
                    {"action": action, "vulnerability_flag": flag if flag and actor.get("_mock_role") != "admin" else None})


@app.post("/lab/v1/resources/{resource_id}/actions/{action}", include_in_schema=False)
def lab_transition(resource_id: str, action: str, request: Request) -> JSONResponse:
    actor = lab_actor(request)
    if not actor:
        return response(request, "/lab/v1/resources/{resource_id}/actions/{action}", {"ErrorMessage": "Valid lab bearer token required"}, 401)
    resource = db["lab_resources"].find_one({"ID": resource_id})
    if not resource:
        return response(request, "/lab/v1/resources/{resource_id}/actions/{action}", {"ErrorMessage": "Resource not found"}, 404, actor)
    role, state = actor.get("_mock_role"), resource.get("State")
    new_state = None
    flag = None
    authorized = lab_is_owner(actor, resource) or role == "admin"
    if action == "request_return" and resource.get("ResourceType") == "order" and role == "customer" and authorized and state == "delivered":
        new_state = "return_pending"
    elif action == "refund" and resource.get("ResourceType") == "order" and role in {"customer", "admin"} and authorized:
        case_id = request.headers.get("x-lab-case-id")
        flag = "AUTHZ-013" if resource_id == "order-b-001" else (case_id if case_id in {"AUTHZ-014", "AUTHZ-020"} else ("AUTHZ-014" if state == "returned" else None))
        if state == "return_pending":
            new_state = "returned"
        elif flag and lab_vulnerability_enabled(flag) and (resource_id != "order-b-001" or lab_case_actor(actor, "actor-customer-b")):
            new_state = "returned"
    elif action == "approve_refund" and role == "admin" and state == "return_pending":
        new_state = "returned"
    elif action == "assign" and resource.get("ResourceType") == "ticket" and role in {"support", "admin"} and state == "open":
        new_state = "assigned"
    elif action == "close" and resource.get("ResourceType") == "ticket":
        flag = "AUTHZ-015"
        if role in {"support", "admin"} and state == "assigned":
            new_state = "closed"
        elif lab_vulnerability_enabled(flag) and lab_case_actor(actor, "actor-customer-a") and state == "open":
            new_state = "closed"
    if not new_state:
        return response(request, "/lab/v1/resources/{resource_id}/actions/{action}",
                        {"ErrorMessage": "Action is not allowed in the current role/state"}, 409 if authorized else 403, actor,
                        {"resource_id": resource_id, "action": action, "state_before": state, "state_after": state})
    vulnerable = bool(flag and lab_vulnerability_enabled(flag) and (action != "refund" or state != "return_pending"))
    db["lab_resources"].update_one({"ID": resource_id}, {"$set": {"State": new_state}})
    return response(request, "/lab/v1/resources/{resource_id}/actions/{action}", {"SuccessStatus": True, "State": new_state}, 200, actor,
                    {"resource_id": resource_id, "action": action, "state_before": state, "state_after": new_state, "vulnerability_flag": flag if vulnerable else None})


@app.api_route("/{full_path:path}", methods=[m.upper() for m in SAFE_METHODS])
async def dispatch(full_path: str, request: Request) -> JSONResponse:
    path = "/" + full_path.strip("/")
    method = request.method.lower()
    matched = None
    for pattern, names, template, operations in ROUTES:
        match = pattern.fullmatch(path)
        if match and method in operations:
            matched = (template, operations[method], dict(zip(names, match.groups())))
            break
    if not matched:
        return response(request, path, {"ErrorMessage": "Endpoint not found in supplied OpenAPI spec"}, 404)

    template, operation, params = matched
    coll = db[collection_for(template)]
    actor = local_user_from_request(request)
    security = operation.get("security", SPEC.get("security", []))
    is_sign_in = template.endswith("/sign-in")
    # All operations declaring a security requirement need a valid local bearer token.
    # Scope/permission authorization is intentionally left to the dedicated lab policy
    # layer; the original spec's scopes are permission names, not the seed Roles field.
    if security and not is_sign_in and (actor is None or actor.get("_mock_role") not in {"customer", "supplier"}):
        return response(request, template, {"ErrorMessage": "Valid local bearer token required"}, 401)

    query: dict[str, Any] = {}
    if "ID" in params:
        if "/orders/{ID}/items" in template:
            query["OrderID"] = params["ID"]
        else:
            numeric = "yearly-reports" in template or "quarterly-reports" in template
            query = id_query(params["ID"], numeric=numeric)
    if "ProductID" in params:
        query["ProductID"] = params["ProductID"]
    if "CustomerID" in params:
        query["CustomerID"] = params["CustomerID"]
    if "Name" in params:
        query["Name"] = {"$regex": re.escape(params["Name"]), "$options": "i"} if template.endswith("/count") else params["Name"]
    if "City" in params:
        query["City"] = params["City"]

    # Current-user and current-supplier routes are always derived from the token,
    # never from a client-supplied owner ID.
    if "current-user" in template or template.endswith("/current-supplier-company"):
        if actor is None:
            return response(request, template, {"ErrorMessage": "Authentication required"}, 401)
        owner_id = actor.get("ID")
        if template.endswith(("/customers/current-user", "/suppliers/current-user")):
            query = {"Email": actor.get("Email")}
        elif "roles/current-user" in template:
            return response(request, template, {"Roles": actor.get("Roles", [])}, 200, actor)
        elif "customers" in template:
            query = {"CustomerID": owner_id}
        elif "products" in template:
            query = {"SupplierID": owner_id}
        elif "supplier-companies" in template:
            query = {"SupplierID": owner_id}

    # GET/read operations.
    if method == "get":
        if template.endswith("/count"):
            return response(request, template, {"Count": coll.count_documents(query)}, 200, actor)
        if template.endswith("/photo") or template.endswith("/certificates-of-incorporation"):
            result = coll.find_one(query)
            if result is None:
                return response(request, template, {"ErrorMessage": "File not found"}, 404, actor)
            encoded = result.get("PNGPhotoFileBase64") or result.get("CertificateOfIncorporationPDFBase64") or ""
            return response(request, template, {"Base64": encoded}, 200, actor)
        if "ID" in params and "/orders/{ID}/items" not in template:
            result = coll.find_one(query)
            if result is None:
                return response(request, template, {"ErrorMessage": "Record not found"}, 404, actor)
            return response(request, template, result, 200, actor)
        if template.endswith(("/customers/current-user", "/suppliers/current-user", "/supplier-companies/current-user")):
            result = coll.find_one(query)
            if result is None:
                return response(request, template, {"ErrorMessage": "Record not found"}, 404, actor)
            return response(request, template, result, 200, actor)
        return response(request, template, list(coll.find(query).limit(500)), 200, actor)

    # Parse JSON or multipart bodies once.
    incoming: dict[str, Any] = {}
    if method in {"post", "put", "patch"}:
        content_type = request.headers.get("content-type", "").lower()
        if "multipart/form-data" in content_type:
            form = await request.form()
            for key, value in form.multi_items():
                if hasattr(value, "read"):
                    incoming[key] = base64.b64encode(await value.read()).decode("ascii")
                else:
                    incoming[key] = str(value)
        else:
            try:
                body = await request.json()
                incoming = body if isinstance(body, dict) else {"value": body}
            except (ValueError, json.JSONDecodeError):
                incoming = {}
    record = body_record(incoming)

    if method == "post":
        if is_sign_in:
            role = "supplier" if "/suppliers/" in template else "customer"
            user = db[role + "s"].find_one({"Email": incoming.get("Email"), "Password": incoming.get("Password")})
            if not user:
                return response(request, template, {"ErrorMessage": "Invalid email or password"}, 401)
            return response(request, template, {"Token": f"local:{role}:{user.get('Email')}", "TokenType": "Bearer"}, 200, {**user, "_mock_role": role}, expose_token=True)

        if template == "/api/v1/authentication/customers/passwords/resets":
            # This mock has no email/SMS delivery or OTP verification service.
            # Do not fall through to generic record creation or mutate a password.
            return response(request, template,
                            {"ErrorMessage": "Password reset is unavailable: OTP delivery/verification is not configured"},
                            501, actor)

        if template.startswith("/api/v1/authentication/customers/passwords/resets/"):
            # No email/SMS provider is wired into this local mock.
            return response(request, template,
                            {"ErrorMessage": "Password reset is unavailable: OTP delivery is not configured"},
                            501, actor)

        if template.endswith("/products/photo"):
            product_id = record.get("ProductID")
            encoded = record.get("ProductPNGFormFile", "")
            updated = db["products"].update_one({"ID": product_id}, {"$set": {"PNGPhotoFileBase64": encoded}})
            return response(request, template, {"SuccessStatus": updated.matched_count > 0}, 200, actor)
        if template.endswith("/certificates-of-incorporation"):
            company_id = record.get("CompanyID")
            encoded = record.get("CertificateOfIncorporationPDFFormFile", "")
            updated = db["supplier_companies"].update_one({"ID": company_id}, {"$set": {"CertificateOfIncorporationPDFBase64": encoded}})
            return response(request, template, {"SuccessStatus": updated.matched_count > 0}, 200, actor)

        # Server-generated identifiers are canonical; never accept client _id.
        record.pop("_id", None)
        record.setdefault("ID", str(uuid.uuid4()))
        if "current-user" in template:
            if actor is None:
                return response(request, template, {"ErrorMessage": "Authentication required"}, 401)
            if "customers" in template:
                record["CustomerID"] = actor.get("ID")
            elif "products" in template:
                record["SupplierID"] = actor.get("ID")
        if template.endswith("/customers/orders") and actor:
            record["CustomerID"] = actor.get("ID")
        if "orders/items" in template:
            order_id = record.get("OrderID")
            order_items = record.get("OrderItems", [])
            if not isinstance(order_items, list):
                return response(request, template, {"ErrorMessage": "OrderItems must be a list"}, 400, actor)
            items = [{**item, "ID": str(uuid.uuid4()), "OrderID": order_id} for item in order_items if isinstance(item, dict)]
            if items:
                db["customer_order_items"].insert_many(items)
            return response(request, template, {"SuccessStatus": True, "Message": f"Added {len(items)} item(s)"}, 200, actor)
        coll.insert_one(record)
        return response(request, template, {"SuccessStatus": True, "ID": record["ID"]}, 201, actor)

    if method in {"put", "patch"}:
        # Map command DTO identifiers to the actual collection's canonical ID field.
        id_fields_by_collection = {
            "products": ("ProductID", "ID"),
            "supplier_companies": ("SupplierCompanyID", "CompanyID", "ID"),
            "customers": ("CustomerID", "ID"),
            "suppliers": ("SupplierID", "ID"),
            "customer_orders": ("OrderID", "ID"),
        }
        id_fields = id_fields_by_collection.get(coll.name, ("ID",))
        body_id_key = next((key for key in id_fields if key in record), None)
        if body_id_key:
            identifier = record.pop(body_id_key)
            update_query = {"ID": identifier}
        elif query:
            update_query = query
        elif "current-user" in template and actor:
            if "customers" in template:
                update_query = {"ID": actor.get("ID")}
            elif "products" in template:
                update_query = {"SupplierID": actor.get("ID")}
            else:
                update_query = {"SupplierID": actor.get("ID")}
        else:
            return response(request, template, {"ErrorMessage": "Provide a resource ID"}, 400, actor)
        record.pop("_id", None)
        # Never permit a request body to overwrite the canonical ID.
        record.pop("ID", None)
        result = coll.update_one(update_query, {"$set": record}, upsert=False)
        return response(request, template, {"SuccessStatus": result.modified_count > 0, "MatchedCount": result.matched_count}, 200, actor)

    if method == "delete":
        if not query:
            return response(request, template, {"ErrorMessage": "Delete requires a resource identifier"}, 400, actor)
        result = coll.delete_one(query)
        return response(request, template, {"SuccessStatus": result.deleted_count > 0}, 200, actor)

    return response(request, template, {"ErrorMessage": "Method not implemented"}, 405, actor)
