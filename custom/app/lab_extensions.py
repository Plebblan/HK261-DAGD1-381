"""Lab extension routes: new resource types (invoice, payout) and new transitions
on existing types (ticket escalation, order reviews).

Written to raise the lab-layer operation/workflow-step count past the >=30 KPI
without touching app/main.py. Reuses the same helpers main.py already exports
(actor resolution, response/audit envelope, flag toggles) so behaviour matches
the rest of the Cyber Range: SAFE BY DEFAULT, each planted flaw gated behind
`lab_vulnerability_enabled(<flag>)`, off unless explicitly enabled.

Import this module once (see app/__init__.py) so its @app.<verb> decorators
register on the shared FastAPI app before the server starts.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

from app.main import app, db, lab_actor, lab_case_actor, lab_vulnerability_enabled, response

# --------------------------------------------------------------------------- helpers
def _actor_or_401(request: Request, template: str) -> dict[str, Any] | JSONResponse:
    actor = lab_actor(request)
    if not actor:
        return response(request, template, {"ErrorMessage": "Valid lab bearer token required"}, 401)
    return actor


def _not_found(request: Request, template: str, actor):
    return response(request, template, {"ErrorMessage": "Resource not found"}, 404, actor)


def _forbidden(request: Request, template: str, actor, **evidence):
    return response(request, template, {"ErrorMessage": "Forbidden"}, 403, actor, evidence or None)


def _conflict(request: Request, template: str, actor, state, **evidence):
    return response(request, template, {"ErrorMessage": f"Not allowed from state '{state}'"}, 409, actor, evidence or None)


def _is_admin(actor) -> bool:
    return actor.get("_mock_role") == "admin"


def _is_owner(actor, doc, owner_field: str = "OwnerID") -> bool:
    return doc.get(owner_field) == actor.get("ID")


def _same_tenant(actor, doc, tenant_field: str = "TenantID") -> bool:
    return doc.get(tenant_field) == actor.get("TenantID")


# =============================================================================
# INVOICE  (supplier billing document; tenant-scoped financial resource)
# States: draft -> submitted -> approved -> paid ; draft/submitted -> voided
# Owner: the supplier company (TenantID). Submit = supplier; approve/pay = admin.
# =============================================================================
INVOICE_TEMPLATE_LIST = "/lab/v1/invoices"
INVOICE_TEMPLATE_ITEM = "/lab/v1/invoices/{invoice_id}"


@app.get(INVOICE_TEMPLATE_LIST, include_in_schema=False)
def lab_list_invoices(request: Request, status: str | None = None) -> JSONResponse:
    actor = _actor_or_401(request, INVOICE_TEMPLATE_LIST)
    if isinstance(actor, JSONResponse):
        return actor
    query: dict[str, Any] = {} if status is None else {"Status": status}
    docs = list(db["lab_invoices"].find(query).limit(500))
    role = actor.get("_mock_role")
    visible = [d for d in docs if role == "admin" or _same_tenant(actor, d)]
    return response(request, INVOICE_TEMPLATE_LIST, visible, 200, actor,
                    {"returned_resource_ids": [d.get("ID") for d in visible]})


@app.post(INVOICE_TEMPLATE_LIST, include_in_schema=False)
async def lab_create_invoice(request: Request) -> JSONResponse:
    actor = _actor_or_401(request, INVOICE_TEMPLATE_LIST)
    if isinstance(actor, JSONResponse):
        return actor
    if actor.get("_mock_role") not in {"supplier", "admin"}:
        return _forbidden(request, INVOICE_TEMPLATE_LIST, actor)
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    amount = body.get("Amount")
    if not isinstance(amount, (int, float)) or amount <= 0:
        return response(request, INVOICE_TEMPLATE_LIST, {"ErrorMessage": "Amount must be a positive number"}, 400, actor)
    doc = {"ID": str(uuid.uuid4()), "TenantID": actor.get("TenantID"), "OwnerID": actor.get("ID"),
           "Amount": float(amount), "LineItems": body.get("LineItems", []) if isinstance(body.get("LineItems"), list) else [],
           "Status": "draft", "CreatedAt": datetime.now(timezone.utc).isoformat()}
    db["lab_invoices"].insert_one(doc)
    return response(request, INVOICE_TEMPLATE_LIST, {"SuccessStatus": True, "ID": doc["ID"]}, 201, actor)


@app.get(INVOICE_TEMPLATE_ITEM, include_in_schema=False)
def lab_get_invoice(invoice_id: str, request: Request) -> JSONResponse:
    actor = _actor_or_401(request, INVOICE_TEMPLATE_ITEM)
    if isinstance(actor, JSONResponse):
        return actor
    doc = db["lab_invoices"].find_one({"ID": invoice_id})
    if not doc:
        return _not_found(request, INVOICE_TEMPLATE_ITEM, actor)
    # AUTHZ-INV-01 (planted, off by default): supplier from another tenant reads a foreign invoice.
    vulnerable = lab_vulnerability_enabled("AUTHZ-INV-01")
    if not (_is_admin(actor) or _same_tenant(actor, doc)) and not vulnerable:
        return _forbidden(request, INVOICE_TEMPLATE_ITEM, actor, resource_id=invoice_id, tenant_id=doc.get("TenantID"))
    return response(request, INVOICE_TEMPLATE_ITEM, doc, 200, actor,
                    {"resource_id": invoice_id, "tenant_id": doc.get("TenantID"),
                     "vulnerability_flag": "AUTHZ-INV-01" if vulnerable and not _same_tenant(actor, doc) and not _is_admin(actor) else None})


@app.patch(INVOICE_TEMPLATE_ITEM, include_in_schema=False)
async def lab_update_invoice(invoice_id: str, request: Request) -> JSONResponse:
    actor = _actor_or_401(request, INVOICE_TEMPLATE_ITEM)
    if isinstance(actor, JSONResponse):
        return actor
    doc = db["lab_invoices"].find_one({"ID": invoice_id})
    if not doc:
        return _not_found(request, INVOICE_TEMPLATE_ITEM, actor)
    if not (_is_owner(actor, doc) or _is_admin(actor)):
        return _forbidden(request, INVOICE_TEMPLATE_ITEM, actor, resource_id=invoice_id)
    if doc.get("Status") != "draft" and not _is_admin(actor):
        return _conflict(request, INVOICE_TEMPLATE_ITEM, actor, doc.get("Status"), resource_id=invoice_id)
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        return response(request, INVOICE_TEMPLATE_ITEM, {"ErrorMessage": "JSON object required"}, 400, actor)
    # AUTHZ-INV-02 (planted, off by default): non-admin edits Amount directly (should be line-item-derived only).
    allowed = {"LineItems"}
    vulnerable = "Amount" in body and lab_vulnerability_enabled("AUTHZ-INV-02") and not _is_admin(actor)
    if set(body) - allowed and not vulnerable and not _is_admin(actor):
        return response(request, INVOICE_TEMPLATE_ITEM, {"ErrorMessage": "Only LineItems is editable"}, 400, actor,
                        {"resource_id": invoice_id, "state_before": doc.get("Status")})
    update = {k: v for k, v in body.items() if k in allowed or _is_admin(actor) or (k == "Amount" and vulnerable)}
    before = doc.get("Status")
    if update:
        db["lab_invoices"].update_one({"ID": invoice_id}, {"$set": update})
    after = db["lab_invoices"].find_one({"ID": invoice_id}) or doc
    return response(request, INVOICE_TEMPLATE_ITEM, {"SuccessStatus": bool(update), "Invoice": after}, 200, actor,
                    {"resource_id": invoice_id, "state_before": before, "state_after": after.get("Status"),
                     "changed_fields": list(update), "vulnerability_flag": "AUTHZ-INV-02" if vulnerable and "Amount" in update else None})


@app.delete(INVOICE_TEMPLATE_ITEM, include_in_schema=False)
def lab_delete_invoice(invoice_id: str, request: Request) -> JSONResponse:
    actor = _actor_or_401(request, INVOICE_TEMPLATE_ITEM)
    if isinstance(actor, JSONResponse):
        return actor
    doc = db["lab_invoices"].find_one({"ID": invoice_id})
    if not doc:
        return _not_found(request, INVOICE_TEMPLATE_ITEM, actor)
    if not (_is_owner(actor, doc) or _is_admin(actor)):
        return _forbidden(request, INVOICE_TEMPLATE_ITEM, actor, resource_id=invoice_id)
    if doc.get("Status") != "draft" and not _is_admin(actor):
        return _conflict(request, INVOICE_TEMPLATE_ITEM, actor, doc.get("Status"), resource_id=invoice_id)
    db["lab_invoices"].delete_one({"ID": invoice_id})
    return response(request, INVOICE_TEMPLATE_ITEM, {"SuccessStatus": True}, 200, actor, {"resource_id": invoice_id, "deleted": True})


def _invoice_transition(request: Request, invoice_id: str, action: str, from_states: set[str], to_state: str,
                        role_ok, flag: str | None = None, attacker_alias: str | None = None) -> JSONResponse:
    template = f"/lab/v1/invoices/{{invoice_id}}/{action}"
    actor = _actor_or_401(request, template)
    if isinstance(actor, JSONResponse):
        return actor
    doc = db["lab_invoices"].find_one({"ID": invoice_id})
    if not doc:
        return _not_found(request, template, actor)
    state = doc.get("Status")
    authorized = role_ok(actor, doc)
    vulnerable = bool(flag and lab_vulnerability_enabled(flag) and attacker_alias and lab_case_actor(actor, attacker_alias))
    if not (authorized or vulnerable):
        return _forbidden(request, template, actor, resource_id=invoice_id, action=action)
    if state not in from_states:
        return _conflict(request, template, actor, state, resource_id=invoice_id, action=action)
    db["lab_invoices"].update_one({"ID": invoice_id}, {"$set": {"Status": to_state}})
    return response(request, template, {"SuccessStatus": True, "Status": to_state}, 200, actor,
                    {"resource_id": invoice_id, "action": action, "state_before": state, "state_after": to_state,
                     "vulnerability_flag": flag if vulnerable else None})


@app.post("/lab/v1/invoices/{invoice_id}/submit", include_in_schema=False)
def lab_invoice_submit(invoice_id: str, request: Request) -> JSONResponse:
    return _invoice_transition(request, invoice_id, "submit", {"draft"}, "submitted",
                               role_ok=lambda a, d: _is_owner(a, d) or _is_admin(a))


@app.post("/lab/v1/invoices/{invoice_id}/approve", include_in_schema=False)
def lab_invoice_approve(invoice_id: str, request: Request) -> JSONResponse:
    # AUTHZ-INV-03 (planted, off by default): a supplier self-approves their own invoice.
    return _invoice_transition(request, invoice_id, "approve", {"submitted"}, "approved",
                               role_ok=lambda a, d: _is_admin(a),
                               flag="AUTHZ-INV-03", attacker_alias="actor-supplier-a")


@app.post("/lab/v1/invoices/{invoice_id}/pay", include_in_schema=False)
def lab_invoice_pay(invoice_id: str, request: Request) -> JSONResponse:
    return _invoice_transition(request, invoice_id, "pay", {"approved"}, "paid", role_ok=lambda a, d: _is_admin(a))


@app.post("/lab/v1/invoices/{invoice_id}/void", include_in_schema=False)
def lab_invoice_void(invoice_id: str, request: Request) -> JSONResponse:
    return _invoice_transition(request, invoice_id, "void", {"draft", "submitted"}, "voided",
                               role_ok=lambda a, d: _is_owner(a, d) or _is_admin(a))


# =============================================================================
# PAYOUT  (admin-only financial release; strong BFLA/tenant-isolation target)
# States: pending -> approved -> released
# =============================================================================
@app.get("/lab/v1/payouts", include_in_schema=False)
def lab_list_payouts(request: Request) -> JSONResponse:
    actor = _actor_or_401(request, "/lab/v1/payouts")
    if isinstance(actor, JSONResponse):
        return actor
    role = actor.get("_mock_role")
    # AUTHZ-PAY-01 (planted, off by default): any supplier lists ALL payouts (should be admin-only).
    vulnerable = role == "supplier" and lab_vulnerability_enabled("AUTHZ-PAY-01")
    if role != "admin" and not vulnerable:
        return _forbidden(request, "/lab/v1/payouts", actor)
    docs = list(db["lab_payouts"].find({}).limit(500))
    return response(request, "/lab/v1/payouts", docs, 200, actor,
                    {"returned_resource_ids": [d.get("ID") for d in docs],
                     "vulnerability_flag": "AUTHZ-PAY-01" if vulnerable else None})


@app.get("/lab/v1/payouts/{payout_id}", include_in_schema=False)
def lab_get_payout(payout_id: str, request: Request) -> JSONResponse:
    actor = _actor_or_401(request, "/lab/v1/payouts/{payout_id}")
    if isinstance(actor, JSONResponse):
        return actor
    doc = db["lab_payouts"].find_one({"ID": payout_id})
    if not doc:
        return _not_found(request, "/lab/v1/payouts/{payout_id}", actor)
    if not (_is_admin(actor) or _same_tenant(actor, doc)):
        return _forbidden(request, "/lab/v1/payouts/{payout_id}", actor, resource_id=payout_id)
    return response(request, "/lab/v1/payouts/{payout_id}", doc, 200, actor, {"resource_id": payout_id})


def _payout_transition(request: Request, payout_id: str, action: str, from_states: set[str], to_state: str) -> JSONResponse:
    template = f"/lab/v1/payouts/{{payout_id}}/{action}"
    actor = _actor_or_401(request, template)
    if isinstance(actor, JSONResponse):
        return actor
    doc = db["lab_payouts"].find_one({"ID": payout_id})
    if not doc:
        return _not_found(request, template, actor)
    state = doc.get("Status")
    # AUTHZ-PAY-02 (planted, off by default): supplier approves/releases their own payout.
    vulnerable = lab_vulnerability_enabled("AUTHZ-PAY-02") and _same_tenant(actor, doc) and actor.get("_mock_role") == "supplier"
    if not (_is_admin(actor) or vulnerable):
        return _forbidden(request, template, actor, resource_id=payout_id, action=action)
    if state not in from_states:
        return _conflict(request, template, actor, state, resource_id=payout_id, action=action)
    db["lab_payouts"].update_one({"ID": payout_id}, {"$set": {"Status": to_state}})
    return response(request, template, {"SuccessStatus": True, "Status": to_state}, 200, actor,
                    {"resource_id": payout_id, "action": action, "state_before": state, "state_after": to_state,
                     "vulnerability_flag": "AUTHZ-PAY-02" if vulnerable else None})


@app.post("/lab/v1/payouts/{payout_id}/approve", include_in_schema=False)
def lab_payout_approve(payout_id: str, request: Request) -> JSONResponse:
    return _payout_transition(request, payout_id, "approve", {"pending"}, "approved")


@app.post("/lab/v1/payouts/{payout_id}/release", include_in_schema=False)
def lab_payout_release(payout_id: str, request: Request) -> JSONResponse:
    return _payout_transition(request, payout_id, "release", {"approved"}, "released")


# =============================================================================
# TICKET ESCALATION  (adds cross-tenant admin escalation beyond assign/close)
# States used here: assigned -> escalated -> resolved
# =============================================================================
@app.post("/lab/v1/tickets/{resource_id}/escalate", include_in_schema=False)
def lab_ticket_escalate(resource_id: str, request: Request) -> JSONResponse:
    template = "/lab/v1/tickets/{resource_id}/escalate"
    actor = _actor_or_401(request, template)
    if isinstance(actor, JSONResponse):
        return actor
    doc = db["lab_resources"].find_one({"ID": resource_id})
    if not doc or doc.get("ResourceType") != "ticket":
        return _not_found(request, template, actor)
    role, state = actor.get("_mock_role"), doc.get("State")
    authorized = role in {"support", "admin"} and (role == "admin" or _same_tenant(actor, doc))
    if not authorized:
        return _forbidden(request, template, actor, resource_id=resource_id)
    if state != "assigned":
        return _conflict(request, template, actor, state, resource_id=resource_id)
    db["lab_resources"].update_one({"ID": resource_id}, {"$set": {"State": "escalated"}})
    return response(request, template, {"SuccessStatus": True, "State": "escalated"}, 200, actor,
                    {"resource_id": resource_id, "action": "escalate", "state_before": state, "state_after": "escalated"})


@app.post("/lab/v1/tickets/{resource_id}/resolve", include_in_schema=False)
def lab_ticket_resolve(resource_id: str, request: Request) -> JSONResponse:
    template = "/lab/v1/tickets/{resource_id}/resolve"
    actor = _actor_or_401(request, template)
    if isinstance(actor, JSONResponse):
        return actor
    doc = db["lab_resources"].find_one({"ID": resource_id})
    if not doc or doc.get("ResourceType") != "ticket":
        return _not_found(request, template, actor)
    state = doc.get("State")
    # AUTHZ-TCK-01 (planted, off by default): support (not admin) resolves an escalated ticket from another tenant.
    vulnerable = (lab_vulnerability_enabled("AUTHZ-TCK-01") and actor.get("_mock_role") == "support"
                 and not _same_tenant(actor, doc))
    if actor.get("_mock_role") != "admin" and not vulnerable:
        return _forbidden(request, template, actor, resource_id=resource_id)
    if state != "escalated":
        return _conflict(request, template, actor, state, resource_id=resource_id)
    db["lab_resources"].update_one({"ID": resource_id}, {"$set": {"State": "resolved"}})
    return response(request, template, {"SuccessStatus": True, "State": "resolved"}, 200, actor,
                    {"resource_id": resource_id, "action": "resolve", "state_before": state, "state_after": "resolved",
                     "vulnerability_flag": "AUTHZ-TCK-01" if vulnerable else None})


# =============================================================================
# ORDER REVIEWS  (customer-generated content tied to an order; extra BOPLA surface)
# =============================================================================
@app.post("/lab/v1/orders/{resource_id}/reviews", include_in_schema=False)
async def lab_create_review(resource_id: str, request: Request) -> JSONResponse:
    template = "/lab/v1/orders/{resource_id}/reviews"
    actor = _actor_or_401(request, template)
    if isinstance(actor, JSONResponse):
        return actor
    order = db["lab_resources"].find_one({"ID": resource_id})
    if not order or order.get("ResourceType") != "order":
        return _not_found(request, template, actor)
    if not _is_owner(actor, order):
        return _forbidden(request, template, actor, resource_id=resource_id)
    if order.get("State") not in {"delivered", "returned"}:
        return _conflict(request, template, actor, order.get("State"), resource_id=resource_id)
    try:
        body = await request.json()
    except Exception:
        body = {}
    rating = body.get("Rating") if isinstance(body, dict) else None
    if not isinstance(rating, int) or not (1 <= rating <= 5):
        return response(request, template, {"ErrorMessage": "Rating must be an integer 1..5"}, 400, actor)
    # AUTHZ-REV-01 (planted, off by default): client sets Verified/Featured directly on creation.
    vulnerable = lab_vulnerability_enabled("AUTHZ-REV-01") and bool(set(body) & {"Verified", "Featured"})
    doc = {"ID": str(uuid.uuid4()), "OrderID": resource_id, "OwnerID": actor.get("ID"),
           "Rating": rating, "Comment": str(body.get("Comment", ""))[:1000],
           "Verified": bool(body.get("Verified")) if vulnerable else True,
           "Featured": bool(body.get("Featured")) if vulnerable else False}
    db["lab_reviews"].insert_one(doc)
    return response(request, template, {"SuccessStatus": True, "ID": doc["ID"]}, 201, actor,
                    {"resource_id": doc["ID"], "vulnerability_flag": "AUTHZ-REV-01" if vulnerable else None})


@app.get("/lab/v1/orders/{resource_id}/reviews", include_in_schema=False)
def lab_list_reviews(resource_id: str, request: Request) -> JSONResponse:
    actor = _actor_or_401(request, "/lab/v1/orders/{resource_id}/reviews")
    if isinstance(actor, JSONResponse):
        return actor
    docs = list(db["lab_reviews"].find({"OrderID": resource_id}).limit(200))
    return response(request, "/lab/v1/orders/{resource_id}/reviews", docs, 200, actor)


@app.patch("/lab/v1/reviews/{review_id}", include_in_schema=False)
async def lab_update_review(review_id: str, request: Request) -> JSONResponse:
    template = "/lab/v1/reviews/{review_id}"
    actor = _actor_or_401(request, template)
    if isinstance(actor, JSONResponse):
        return actor
    doc = db["lab_reviews"].find_one({"ID": review_id})
    if not doc:
        return _not_found(request, template, actor)
    if not (_is_owner(actor, doc) or _is_admin(actor)):
        return _forbidden(request, template, actor, resource_id=review_id)
    try:
        body = await request.json()
    except Exception:
        body = {}
    allowed = {"Rating", "Comment"}
    vulnerable = lab_vulnerability_enabled("AUTHZ-REV-02") and bool(set(body) & {"Verified", "Featured"}) and not _is_admin(actor)
    if set(body) - allowed and not vulnerable and not _is_admin(actor):
        return response(request, template, {"ErrorMessage": "Only Rating/Comment are editable"}, 400, actor)
    update = {k: v for k, v in body.items() if k in allowed or _is_admin(actor) or (vulnerable and k in {"Verified", "Featured"})}
    if update:
        db["lab_reviews"].update_one({"ID": review_id}, {"$set": update})
    after = db["lab_reviews"].find_one({"ID": review_id}) or doc
    return response(request, template, {"SuccessStatus": bool(update), "Review": after}, 200, actor,
                    {"resource_id": review_id, "changed_fields": list(update),
                     "vulnerability_flag": "AUTHZ-REV-02" if vulnerable else None})


@app.delete("/lab/v1/reviews/{review_id}", include_in_schema=False)
def lab_delete_review(review_id: str, request: Request) -> JSONResponse:
    template = "/lab/v1/reviews/{review_id}"
    actor = _actor_or_401(request, template)
    if isinstance(actor, JSONResponse):
        return actor
    doc = db["lab_reviews"].find_one({"ID": review_id})
    if not doc:
        return _not_found(request, template, actor)
    if not (_is_owner(actor, doc) or _is_admin(actor)):
        return _forbidden(request, template, actor, resource_id=review_id)
    db["lab_reviews"].delete_one({"ID": review_id})
    return response(request, template, {"SuccessStatus": True}, 200, actor, {"resource_id": review_id, "deleted": True})


# =============================================================================
# AUDIT HISTORY  (read-only trail per resource; pushes path-template operation
# count comfortably past the >=30 KPI without relying on {action} parsing)
# =============================================================================
def _history(request: Request, template: str, resource_id: str, owner_lookup) -> JSONResponse:
    actor = _actor_or_401(request, template)
    if isinstance(actor, JSONResponse):
        return actor
    doc = owner_lookup(resource_id)
    if not doc:
        return _not_found(request, template, actor)
    if not (_is_admin(actor) or _is_owner(actor, doc) or _same_tenant(actor, doc)):
        return _forbidden(request, template, actor, resource_id=resource_id)
    events = list(db["http_audit_events"].find({"evidence.resource_id": resource_id}).limit(200))
    redacted = [{"timestamp": e.get("timestamp"), "method": e.get("method"), "status_code": e.get("status_code"),
                "operation_template": e.get("operation_template")} for e in events]
    return response(request, template, redacted, 200, actor, {"resource_id": resource_id})


@app.get("/lab/v1/invoices/{invoice_id}/history", include_in_schema=False)
def lab_invoice_history(invoice_id: str, request: Request) -> JSONResponse:
    return _history(request, "/lab/v1/invoices/{invoice_id}/history", invoice_id,
                    lambda rid: db["lab_invoices"].find_one({"ID": rid}))


@app.get("/lab/v1/payouts/{payout_id}/history", include_in_schema=False)
def lab_payout_history(payout_id: str, request: Request) -> JSONResponse:
    return _history(request, "/lab/v1/payouts/{payout_id}/history", payout_id,
                    lambda rid: db["lab_payouts"].find_one({"ID": rid}))


@app.get("/lab/v1/resources/{resource_id}/history", include_in_schema=False)
def lab_resource_history(resource_id: str, request: Request) -> JSONResponse:
    return _history(request, "/lab/v1/resources/{resource_id}/history", resource_id,
                    lambda rid: db["lab_resources"].find_one({"ID": rid}))
