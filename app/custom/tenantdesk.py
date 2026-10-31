"""App A - TenantDesk: multi-tenant helpdesk (tickets + documents).
Roles: member < agent < admin. Tenants: acme, globex.
Workflows: ticket (open->in_progress->resolved->closed), document (draft->review->published).
17 planted flaws (TD-01..TD-17); each can be switched on/off independently.
"""
from typing import Literal, Optional

from fastapi import Depends, FastAPI, HTTPException

from pydantic import BaseModel, Field

from .common import Range, add_lab_routes, enabled_from_env, make_auth

FLAWS = [f"TD-{i:02d}" for i in range(1, 18)]
ALLOWED = {"open": ["in_progress"], "in_progress": ["resolved", "open"],
           "resolved": ["closed", "open"], "closed": []}
Role = Literal["member", "agent", "admin"]
Prio = Literal["low", "normal", "high"]
Status = Literal["open", "in_progress", "resolved", "closed"]


def seed():
    def user(i, n, t, r):
        return {"id": i, "username": n, "tenant": t, "role": r, "display_name": n.title(),
                "email": f"{n}@{t}.test", "api_key": f"ak_{n}_synthetic"}
    users = {u["id"]: u for u in [
        user(1, "alice", "acme", "admin"), user(2, "adam", "acme", "agent"),
        user(3, "amy", "acme", "member"), user(4, "ann", "acme", "member"),
        user(5, "gina", "globex", "admin"), user(6, "greg", "globex", "agent"),
        user(7, "gus", "globex", "member")]}
    def ticket(i, t, owner, title, status, assignee=None):
        return {"id": i, "tenant": t, "owner_id": owner, "title": title, "body": "synthetic",
                "priority": "normal", "status": status, "assignee_id": assignee}
    tickets = {t["id"]: t for t in [
        ticket(1001, "acme", 3, "Printer jammed", "open"),
        ticket(1002, "acme", 4, "VPN down", "in_progress", 2),
        ticket(1003, "globex", 7, "Invoice mismatch", "open")]}
    comments = {
        1: {"id": 1, "ticket_id": 1002, "author_id": 2, "body": "Suspect expired cert", "internal": True},
        2: {"id": 2, "ticket_id": 1002, "author_id": 4, "body": "Still down", "internal": False}}
    def doc(i, t, owner, title, vis, status):
        return {"id": i, "tenant": t, "owner_id": owner, "title": title, "content": "synthetic",
                "visibility": vis, "status": status, "shared_with": [], "approved_by": None}
    docs = {d["id"]: d for d in [
        doc(2001, "acme", 3, "Amy private notes", "private", "draft"),
        doc(2002, "acme", 4, "Acme onboarding handbook", "tenant", "published"),
        doc(2003, "globex", 7, "Gus private notes", "private", "draft"),
        doc(2004, "globex", 5, "Globex payroll policy", "tenant", "published")]}
    return {"users": users, "tickets": tickets, "comments": comments, "documents": docs,
            "seq": {"user": 7, "ticket": 1003, "comment": 2, "document": 2004}}


class LoginReq(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    role: Role = "member"
    display_name: Optional[str] = None
    email: Optional[str] = None

class UserPatch(BaseModel):
    display_name: Optional[str] = None
    email: Optional[str] = None
    role: Optional[Role] = None          # present in the shared DTO (realistic mass-assignment surface)

class TicketCreate(BaseModel):
    title: str
    body: str = ""
    priority: Prio = "normal"

class TicketPatch(BaseModel):
    title: Optional[str] = None
    body: Optional[str] = None
    priority: Optional[Prio] = None
    status: Optional[Status] = None
    assignee_id: Optional[int] = None

class CommentCreate(BaseModel):
    body: str
    internal: bool = False

class AssignReq(BaseModel):
    assignee_id: int

class TransitionReq(BaseModel):
    to: Status

class DocCreate(BaseModel):
    title: str
    content: str = ""
    visibility: Literal["private", "tenant"] = "private"

class DocUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None

class ShareReq(BaseModel):
    user_id: int


def create_app(enabled=None):
    rng = Range("tenantdesk", seed, FLAWS, enabled)
    V = rng.vuln
    auth = make_auth(rng)
    app = FastAPI(title="TenantDesk (Cyber Range App A)", version="1.0.0",
                  description="Synthetic multi-tenant helpdesk for authorized security research only.")
    add_lab_routes(app, rng)

    def public(x):
        return {k: x[k] for k in ("id", "username", "tenant", "role", "display_name", "email")}

    def private(x):
        return {**public(x), "api_key": x["api_key"]}

    def get_ticket(tid, u, flaw=None):
        t = rng.db["tickets"].get(tid)
        if not t or t["tenant"] != u["tenant"]:
            raise HTTPException(404, "ticket not found")
        if u["role"] == "member" and t["owner_id"] != u["id"] and not (flaw and V(flaw)):
            raise HTTPException(403, "forbidden")
        return t

    def get_doc(did, u, tenant_flaw=None):
        d = rng.db["documents"].get(did)
        if not d or (d["tenant"] != u["tenant"] and not (tenant_flaw and V(tenant_flaw))):
            raise HTTPException(404, "document not found")
        return d

    # ---------------- auth ----------------
    @app.post("/auth/login", tags=["auth"], operation_id="login")
    def login(b: LoginReq):
        u = next((x for x in rng.db["users"].values() if x["username"] == b.username), None)
        if not u or b.password != f"pw-{u['username']}":
            raise HTTPException(401, "bad credentials")
        return {"token": rng.login(u), "user_id": u["id"], "tenant": u["tenant"], "role": u["role"]}

    @app.post("/auth/logout", tags=["auth"], operation_id="logout")
    def logout(u=Depends(auth)):
        rng.db["sessions"].pop(u["_token"], None)
        return {"status": "logged_out"}

    # ---------------- users ----------------
    @app.get("/users/me", tags=["users"], operation_id="get_me")
    def get_me(u=Depends(auth)):
        return private(rng.db["users"][u["id"]])

    @app.patch("/users/me", tags=["users"], operation_id="patch_me")
    def patch_me(b: UserPatch, u=Depends(auth)):
        f = b.model_dump(exclude_unset=True)
        if "role" in f and not V("TD-04"):                                   # TD-04
            raise HTTPException(403, "role change not permitted")
        rng.db["users"][u["id"]].update(f)
        return private(rng.db["users"][u["id"]])

    @app.get("/users", tags=["users"], operation_id="list_users")
    def list_users(u=Depends(auth)):
        if u["role"] == "member":
            raise HTTPException(403, "forbidden")
        return [public(x) for x in rng.db["users"].values()
                if V("TD-15") or x["tenant"] == u["tenant"]]                  # TD-15

    @app.post("/users", tags=["users"], operation_id="create_user", status_code=201)
    def create_user(b: UserCreate, u=Depends(auth)):
        if not (u["role"] == "admin" or (V("TD-08") and u["role"] == "agent")):  # TD-08
            raise HTTPException(403, "admin only")
        if any(x["username"] == b.username for x in rng.db["users"].values()):
            raise HTTPException(409, "username taken")
        i = rng.next_id("user")
        nu = {"id": i, "username": b.username, "tenant": u["tenant"], "role": b.role,
              "display_name": b.display_name or b.username.title(),
              "email": b.email or f"{b.username}@{u['tenant']}.test", "api_key": f"ak_{b.username}_synthetic"}
        rng.db["users"][i] = nu
        return public(nu)

    @app.get("/users/{user_id}", tags=["users"], operation_id="get_user")
    def get_user(user_id: int, u=Depends(auth)):
        x = rng.db["users"].get(user_id)
        if not x or x["tenant"] != u["tenant"]:
            raise HTTPException(404, "user not found")
        return private(x) if (x["id"] == u["id"] or V("TD-06")) else public(x)   # TD-06

    @app.delete("/users/{user_id}", tags=["users"], operation_id="delete_user")
    def delete_user(user_id: int, u=Depends(auth)):
        if not (u["role"] == "admin" or (V("TD-10") and u["role"] == "agent")):  # TD-10
            raise HTTPException(403, "admin only")
        x = rng.db["users"].get(user_id)
        if not x or x["tenant"] != u["tenant"]:
            raise HTTPException(404, "user not found")
        if x["id"] == u["id"]:
            raise HTTPException(400, "cannot delete self")
        del rng.db["users"][user_id]
        for tok in [t for t, uid in rng.db["sessions"].items() if uid == user_id]:
            del rng.db["sessions"][tok]
        return {"deleted": user_id}

    # ---------------- tickets ----------------
    @app.post("/tickets", tags=["tickets"], operation_id="create_ticket", status_code=201)
    def create_ticket(b: TicketCreate, u=Depends(auth)):
        i = rng.next_id("ticket")
        t = {"id": i, "tenant": u["tenant"], "owner_id": u["id"], "title": b.title, "body": b.body,
             "priority": b.priority, "status": "open", "assignee_id": None}
        rng.db["tickets"][i] = t
        return t

    @app.get("/tickets", tags=["tickets"], operation_id="list_tickets")
    def list_tickets(u=Depends(auth)):
        return [t for t in rng.db["tickets"].values() if t["tenant"] == u["tenant"]
                and (u["role"] != "member" or t["owner_id"] == u["id"])]

    @app.get("/tickets/{ticket_id}", tags=["tickets"], operation_id="get_ticket")
    def get_ticket_ep(ticket_id: int, u=Depends(auth)):
        return get_ticket(ticket_id, u, "TD-01")                                 # TD-01

    @app.patch("/tickets/{ticket_id}", tags=["tickets"], operation_id="patch_ticket")
    def patch_ticket(ticket_id: int, b: TicketPatch, u=Depends(auth)):
        t = get_ticket(ticket_id, u, "TD-03")                                    # TD-03
        f = b.model_dump(exclude_unset=True)
        if u["role"] == "member" and set(f) & {"priority", "status", "assignee_id"} and not V("TD-05"):  # TD-05
            raise HTTPException(403, "members may only edit title/body")
        if f.get("assignee_id") is not None:
            a = rng.db["users"].get(f["assignee_id"])
            if not a or a["tenant"] != t["tenant"]:
                raise HTTPException(400, "invalid assignee")
        t.update(f)
        return t

    @app.delete("/tickets/{ticket_id}", tags=["tickets"], operation_id="delete_ticket")
    def delete_ticket(ticket_id: int, u=Depends(auth)):
        t = get_ticket(ticket_id, u)
        if u["role"] == "agent":
            raise HTTPException(403, "forbidden")
        del rng.db["tickets"][t["id"]]
        for cid in [c for c, x in rng.db["comments"].items() if x["ticket_id"] == t["id"]]:
            del rng.db["comments"][cid]
        return {"deleted": ticket_id}

    @app.post("/tickets/{ticket_id}/comments", tags=["tickets"], operation_id="add_comment", status_code=201)
    def add_comment(ticket_id: int, b: CommentCreate, u=Depends(auth)):
        t = get_ticket(ticket_id, u)
        i = rng.next_id("comment")
        c = {"id": i, "ticket_id": t["id"], "author_id": u["id"], "body": b.body,
             "internal": bool(b.internal and u["role"] != "member")}
        rng.db["comments"][i] = c
        return c

    @app.get("/tickets/{ticket_id}/comments", tags=["tickets"], operation_id="list_comments")
    def list_comments(ticket_id: int, u=Depends(auth)):
        t = get_ticket(ticket_id, u)
        return [c for c in rng.db["comments"].values() if c["ticket_id"] == t["id"]
                and (not c["internal"] or u["role"] != "member" or V("TD-07"))]  # TD-07

    @app.post("/tickets/{ticket_id}/assign", tags=["tickets"], operation_id="assign_ticket")
    def assign_ticket(ticket_id: int, b: AssignReq, u=Depends(auth)):
        if u["role"] == "member":
            raise HTTPException(403, "forbidden")
        t = get_ticket(ticket_id, u)
        a = rng.db["users"].get(b.assignee_id)
        if not a:
            raise HTTPException(404, "assignee not found")
        if a["tenant"] != u["tenant"] and not V("TD-11"):                        # TD-11
            raise HTTPException(400, "assignee must belong to your tenant")
        if a["role"] == "member":
            raise HTTPException(400, "assignee must be agent/admin")
        t["assignee_id"] = a["id"]
        return t

    @app.post("/tickets/{ticket_id}/transition", tags=["tickets"], operation_id="transition_ticket")
    def transition(ticket_id: int, b: TransitionReq, u=Depends(auth)):
        t = get_ticket(ticket_id, u)
        cur = t["status"]
        if u["role"] == "member":
            ok = cur == "resolved" and b.to in ("closed", "open")
        else:
            ok = b.to in ALLOWED[cur]
            if V("TD-12"):                                                       # TD-12
                ok = b.to != cur
        if not ok:
            raise HTTPException(409, f"illegal transition {cur}->{b.to}")
        t["status"] = b.to
        return t

    # ---------------- documents ----------------
    def can_read(d, u):
        return (d["owner_id"] == u["id"] or u["role"] == "admin" or u["id"] in d["shared_with"]
                or (d["visibility"] == "tenant" and d["status"] == "published"))

    @app.post("/documents", tags=["documents"], operation_id="create_document", status_code=201)
    def create_doc(b: DocCreate, u=Depends(auth)):
        i = rng.next_id("document")
        d = {"id": i, "tenant": u["tenant"], "owner_id": u["id"], "title": b.title, "content": b.content,
             "visibility": b.visibility, "status": "draft", "shared_with": [], "approved_by": None}
        rng.db["documents"][i] = d
        return d

    @app.get("/documents", tags=["documents"], operation_id="list_documents")
    def list_docs(u=Depends(auth)):
        return [d for d in rng.db["documents"].values() if d["tenant"] == u["tenant"] and can_read(d, u)]

    @app.get("/documents/{doc_id}", tags=["documents"], operation_id="get_document")
    def get_doc_ep(doc_id: int, u=Depends(auth)):
        d = get_doc(doc_id, u, "TD-02")                                          # TD-02
        if not can_read(d, u):
            raise HTTPException(403, "forbidden")
        return d

    @app.put("/documents/{doc_id}", tags=["documents"], operation_id="update_document")
    def update_doc(doc_id: int, b: DocUpdate, u=Depends(auth)):
        d = get_doc(doc_id, u)
        if d["owner_id"] != u["id"] and u["role"] != "admin":
            raise HTTPException(403, "forbidden")
        if d["status"] != "draft" and not (d["status"] == "published" and V("TD-14")):  # TD-14
            raise HTTPException(409, "only drafts are editable")
        d.update(b.model_dump(exclude_unset=True))
        return d

    @app.delete("/documents/{doc_id}", tags=["documents"], operation_id="delete_document")
    def delete_doc(doc_id: int, u=Depends(auth)):
        d = get_doc(doc_id, u)
        if d["owner_id"] != u["id"] and u["role"] != "admin" and not V("TD-16"):  # TD-16
            raise HTTPException(403, "forbidden")
        del rng.db["documents"][doc_id]
        return {"deleted": doc_id}

    @app.post("/documents/{doc_id}/share", tags=["documents"], operation_id="share_document")
    def share_doc(doc_id: int, b: ShareReq, u=Depends(auth)):
        d = get_doc(doc_id, u)
        if d["owner_id"] != u["id"] and u["role"] != "admin":
            raise HTTPException(403, "forbidden")
        tgt = rng.db["users"].get(b.user_id)
        if not tgt:
            raise HTTPException(404, "user not found")
        if tgt["tenant"] != d["tenant"] and not V("TD-17"):                      # TD-17
            raise HTTPException(400, "cannot share across tenants")
        if tgt["id"] not in d["shared_with"]:
            d["shared_with"].append(tgt["id"])
        return d

    @app.post("/documents/{doc_id}/submit", tags=["documents"], operation_id="submit_document")
    def submit_doc(doc_id: int, u=Depends(auth)):
        d = get_doc(doc_id, u)
        if d["owner_id"] != u["id"]:
            raise HTTPException(403, "owner only")
        if d["status"] != "draft":
            raise HTTPException(409, "only drafts can be submitted")
        d["status"] = "review"
        return d

    @app.post("/documents/{doc_id}/approve", tags=["documents"], operation_id="approve_document")
    def approve_doc(doc_id: int, u=Depends(auth)):
        if u["role"] not in ("agent", "admin"):
            raise HTTPException(403, "forbidden")
        d = get_doc(doc_id, u)
        if d["status"] != "review":
            raise HTTPException(409, "document is not in review")
        if d["owner_id"] == u["id"] and not V("TD-13"):                          # TD-13
            raise HTTPException(403, "authors cannot approve their own documents")
        d["status"], d["approved_by"] = "published", u["id"]
        return d

    # ---------------- admin ----------------
    @app.get("/admin/audit", tags=["admin"], operation_id="get_audit")
    def get_audit(u=Depends(auth)):
        if not (u["role"] == "admin" or (V("TD-09") and u["role"] == "agent")):  # TD-09
            raise HTTPException(403, "admin only")
        return [a for a in rng.audit if a["tenant"] == u["tenant"]]

    return app


app = create_app(enabled_from_env(FLAWS))
