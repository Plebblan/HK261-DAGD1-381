"""App B - ShopFlow: multi-merchant e-commerce back-office (orders, coupons, refunds).
Roles: customer < staff < merchant_admin. Tenants (merchants): acme-shop, globex-shop.
Workflows: order (draft->paid->shipped->delivered | cancelled | refunded), refund (pending->approved).
14 planted flaws (SF-01..SF-14); each can be switched on/off independently.
"""
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from .common import Range, add_lab_routes, enabled_from_env, make_auth

FLAWS = [f"SF-{i:02d}" for i in range(1, 15)]
LIVE = ("paid", "shipped", "delivered")


def seed():
    def user(i, n, t, r):
        return {"id": i, "username": n, "tenant": t, "role": r, "display_name": n.title()}
    users = {u["id"]: u for u in [
        user(1, "olga", "acme-shop", "merchant_admin"), user(2, "sam", "acme-shop", "staff"),
        user(3, "cathy", "acme-shop", "customer"), user(4, "carl", "acme-shop", "customer"),
        user(5, "greta", "globex-shop", "merchant_admin"), user(6, "steve", "globex-shop", "staff"),
        user(7, "chris", "globex-shop", "customer")]}
    products = {p["id"]: p for p in [
        {"id": 501, "tenant": "acme-shop", "name": "Acme Mug", "price": 1500, "cost_price": 600, "stock": 50},
        {"id": 502, "tenant": "acme-shop", "name": "Acme Shirt", "price": 3000, "cost_price": 1100, "stock": 20},
        {"id": 601, "tenant": "globex-shop", "name": "Globex Lamp", "price": 5000, "cost_price": 2000, "stock": 10}]}
    coupons = {
        "ACME10": {"code": "ACME10", "tenant": "acme-shop", "percent": 10, "max_uses": 1, "uses": 0},
        "GLOBEX15": {"code": "GLOBEX15", "tenant": "globex-shop", "percent": 15, "max_uses": 5, "uses": 0}}
    def order(i, t, cust, pid, qty, status, paid=False):
        p = products[pid]
        total = p["price"] * qty
        return {"id": i, "tenant": t, "customer_id": cust, "address": "1 Synthetic St",
                "items": [{"product_id": pid, "qty": qty, "unit_price": p["price"]}],
                "subtotal": total, "discount": 0, "total": total, "coupon": None, "status": status,
                "paid_amount": total if paid else 0, "refunded_total": 0}
    orders = {o["id"]: o for o in [
        order(7001, "acme-shop", 3, 501, 1, "draft"),
        order(7002, "acme-shop", 4, 502, 1, "draft"),
        order(7003, "acme-shop", 3, 501, 2, "paid", True),
        order(7004, "globex-shop", 7, 601, 1, "draft"),
        order(7005, "acme-shop", 3, 501, 1, "shipped", True)]}
    return {"users": users, "products": products, "coupons": coupons, "orders": orders, "refunds": {},
            "seq": {"order": 7005, "refund": 9000, "product": 800}}


class LoginReq(BaseModel):
    username: str
    password: str

class OrderItem(BaseModel):
    product_id: int
    qty: int = Field(ge=1, le=20)
    unit_price: Optional[int] = Field(default=None, ge=0)   # client-visible in spec (realistic)

class OrderCreate(BaseModel):
    items: list[OrderItem] = Field(min_length=1)
    address: str = ""

class OrderPatch(BaseModel):
    address: Optional[str] = None
    total: Optional[int] = Field(default=None, ge=0)

class CouponApply(BaseModel):
    code: str

class RefundCreate(BaseModel):
    amount: int = Field(gt=0)
    reason: str = ""

class ProductCreate(BaseModel):
    name: str
    price: int = Field(gt=0)
    cost_price: int = Field(default=0, ge=0)
    stock: int = Field(default=0, ge=0)

class ProductPatch(BaseModel):
    price: Optional[int] = Field(default=None, gt=0)
    stock: Optional[int] = Field(default=None, ge=0)

class CouponCreate(BaseModel):
    code: str
    percent: int = Field(ge=1, le=90)
    max_uses: int = Field(default=1, ge=1)


def create_app(enabled=None):
    rng = Range("shopflow", seed, FLAWS, enabled)
    V = rng.vuln
    auth = make_auth(rng)
    app = FastAPI(title="ShopFlow (Cyber Range App B)", version="1.0.0",
                  description="Synthetic multi-merchant shop back-office for authorized security research only.")
    add_lab_routes(app, rng)

    def staff_like(u):
        return u["role"] in ("staff", "merchant_admin")

    def load_order(oid, u, owner_flaw=None, tenant_flaw=None):
        o = rng.db["orders"].get(oid)
        if not o or (o["tenant"] != u["tenant"] and not (tenant_flaw and V(tenant_flaw))):
            raise HTTPException(404, "order not found")
        if u["role"] == "customer" and o["customer_id"] != u["id"] and not (owner_flaw and V(owner_flaw)):
            raise HTTPException(403, "forbidden")
        return o

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

    @app.get("/me", tags=["auth"], operation_id="get_me")
    def me(u=Depends(auth)):
        return {k: u[k] for k in ("id", "username", "tenant", "role", "display_name")}

    # ---------------- catalog ----------------
    @app.get("/products", tags=["catalog"], operation_id="list_products")
    def list_products(u=Depends(auth)):
        out = []
        for p in rng.db["products"].values():
            if p["tenant"] == u["tenant"]:
                q = dict(p)
                if u["role"] == "customer" and not V("SF-14"):                   # SF-14
                    q.pop("cost_price")
                out.append(q)
        return out

    @app.post("/products", tags=["catalog"], operation_id="create_product", status_code=201)
    def create_product(b: ProductCreate, u=Depends(auth)):
        if not staff_like(u):
            raise HTTPException(403, "forbidden")
        i = rng.next_id("product")
        p = {"id": i, "tenant": u["tenant"], **b.model_dump()}
        rng.db["products"][i] = p
        return p

    @app.patch("/products/{product_id}", tags=["catalog"], operation_id="patch_product")
    def patch_product(product_id: int, b: ProductPatch, u=Depends(auth)):
        if u["role"] != "merchant_admin":
            raise HTTPException(403, "merchant_admin only")
        p = rng.db["products"].get(product_id)
        if not p or p["tenant"] != u["tenant"]:
            raise HTTPException(404, "product not found")
        p.update(b.model_dump(exclude_unset=True))
        return p

    # ---------------- orders ----------------
    @app.post("/orders", tags=["orders"], operation_id="create_order", status_code=201)
    def create_order(b: OrderCreate, u=Depends(auth)):
        if u["role"] != "customer":
            raise HTTPException(403, "customers only")
        lines, sub = [], 0
        for it in b.items:
            p = rng.db["products"].get(it.product_id)
            if not p or p["tenant"] != u["tenant"]:
                raise HTTPException(404, f"product {it.product_id} not found")
            price = it.unit_price if (it.unit_price is not None and V("SF-05")) else p["price"]  # SF-05
            lines.append({"product_id": p["id"], "qty": it.qty, "unit_price": price})
            sub += price * it.qty
        i = rng.next_id("order")
        o = {"id": i, "tenant": u["tenant"], "customer_id": u["id"], "address": b.address, "items": lines,
             "subtotal": sub, "discount": 0, "total": sub, "coupon": None, "status": "draft",
             "paid_amount": 0, "refunded_total": 0}
        rng.db["orders"][i] = o
        return o

    @app.get("/orders", tags=["orders"], operation_id="list_orders")
    def list_orders(u=Depends(auth)):
        return [o for o in rng.db["orders"].values() if o["tenant"] == u["tenant"]
                and (u["role"] != "customer" or o["customer_id"] == u["id"])]

    @app.get("/orders/{order_id}", tags=["orders"], operation_id="get_order")
    def get_order(order_id: int, u=Depends(auth)):
        return load_order(order_id, u, "SF-01", "SF-02")                         # SF-01, SF-02

    @app.patch("/orders/{order_id}", tags=["orders"], operation_id="patch_order")
    def patch_order(order_id: int, b: OrderPatch, u=Depends(auth)):
        o = load_order(order_id, u, "SF-03")                                     # SF-03
        if o["status"] != "draft":
            raise HTTPException(409, "only draft orders can be edited")
        f = b.model_dump(exclude_unset=True)
        if "total" in f and not V("SF-04"):                                      # SF-04
            raise HTTPException(403, "total is server-computed")
        o.update(f)
        return o

    @app.post("/orders/{order_id}/apply-coupon", tags=["orders"], operation_id="apply_coupon")
    def apply_coupon(order_id: int, b: CouponApply, u=Depends(auth)):
        o = load_order(order_id, u)
        if o["status"] != "draft":
            raise HTTPException(409, "coupons only on draft orders")
        if o["coupon"]:
            raise HTTPException(409, "a coupon is already applied")
        c = rng.db["coupons"].get(b.code.upper())
        if not c or (c["tenant"] != o["tenant"] and not V("SF-13")):             # SF-13
            raise HTTPException(404, "coupon not found")
        if c["uses"] >= c["max_uses"] and not V("SF-11"):                        # SF-11
            raise HTTPException(409, "coupon exhausted")
        c["uses"] += 1
        o["coupon"] = c["code"]
        o["discount"] = o["subtotal"] * c["percent"] // 100
        o["total"] = o["subtotal"] - o["discount"]
        return o

    @app.post("/orders/{order_id}/pay", tags=["orders"], operation_id="pay_order")
    def pay_order(order_id: int, u=Depends(auth)):
        if u["role"] != "customer":
            raise HTTPException(403, "customers only")
        o = load_order(order_id, u)
        if o["status"] != "draft":
            raise HTTPException(409, "order is not payable")
        for it in o["items"]:
            if rng.db["products"][it["product_id"]]["stock"] < it["qty"]:
                raise HTTPException(409, "insufficient stock")
        for it in o["items"]:
            rng.db["products"][it["product_id"]]["stock"] -= it["qty"]
        o["status"], o["paid_amount"] = "paid", o["total"]
        return o

    @app.post("/orders/{order_id}/ship", tags=["orders"], operation_id="ship_order")
    def ship_order(order_id: int, u=Depends(auth)):
        if not (staff_like(u) or V("SF-06")):                                    # SF-06
            raise HTTPException(403, "staff only")
        o = load_order(order_id, u)
        if not (o["status"] == "paid" or (V("SF-09") and o["status"] == "draft")):  # SF-09
            raise HTTPException(409, "order must be paid before shipping")
        o["status"] = "shipped"
        return o

    @app.post("/orders/{order_id}/deliver", tags=["orders"], operation_id="deliver_order")
    def deliver_order(order_id: int, u=Depends(auth)):
        if not staff_like(u):
            raise HTTPException(403, "staff only")
        o = load_order(order_id, u)
        if o["status"] != "shipped":
            raise HTTPException(409, "order is not shipped")
        o["status"] = "delivered"
        return o

    @app.post("/orders/{order_id}/cancel", tags=["orders"], operation_id="cancel_order")
    def cancel_order(order_id: int, u=Depends(auth)):
        o = load_order(order_id, u)
        ok_states = ("draft", "paid") + (("shipped", "delivered") if V("SF-12") else ())  # SF-12
        if o["status"] not in ok_states:
            raise HTTPException(409, f"cannot cancel an order in state {o['status']}")
        o["status"] = "cancelled"
        return o

    @app.get("/orders/{order_id}/invoice", tags=["orders"], operation_id="get_invoice")
    def invoice(order_id: int, u=Depends(auth)):
        o = load_order(order_id, u)
        return {"order_id": o["id"], "lines": o["items"], "discount": o["discount"],
                "total": o["total"], "status": o["status"]}

    # ---------------- refunds ----------------
    @app.post("/orders/{order_id}/refund", tags=["refunds"], operation_id="request_refund", status_code=201)
    def request_refund(order_id: int, b: RefundCreate, u=Depends(auth)):
        o = load_order(order_id, u)
        if o["status"] not in LIVE:
            raise HTTPException(409, "order is not refundable")
        prior = sum(r["amount"] for r in rng.db["refunds"].values()
                    if r["order_id"] == o["id"] and r["status"] in ("pending", "approved"))
        if b.amount > o["paid_amount"] or (not V("SF-10") and prior + b.amount > o["paid_amount"]):  # SF-10
            raise HTTPException(409, "refund exceeds paid amount")
        i = rng.next_id("refund")
        r = {"id": i, "tenant": o["tenant"], "order_id": o["id"], "customer_id": o["customer_id"],
             "amount": b.amount, "reason": b.reason, "status": "pending"}
        rng.db["refunds"][i] = r
        return r

    @app.get("/refunds/{refund_id}", tags=["refunds"], operation_id="get_refund")
    def get_refund(refund_id: int, u=Depends(auth)):
        r = rng.db["refunds"].get(refund_id)
        if not r or r["tenant"] != u["tenant"]:
            raise HTTPException(404, "refund not found")
        if u["role"] == "customer" and r["customer_id"] != u["id"]:
            raise HTTPException(403, "forbidden")
        return r

    @app.post("/refunds/{refund_id}/approve", tags=["refunds"], operation_id="approve_refund")
    def approve_refund(refund_id: int, u=Depends(auth)):
        if not (u["role"] == "merchant_admin" or (V("SF-07") and u["role"] == "staff")):  # SF-07
            raise HTTPException(403, "merchant_admin only")
        r = rng.db["refunds"].get(refund_id)
        if not r or r["tenant"] != u["tenant"]:
            raise HTTPException(404, "refund not found")
        if r["status"] != "pending":
            raise HTTPException(409, "refund is not pending")
        r["status"] = "approved"
        o = rng.db["orders"][r["order_id"]]
        o["refunded_total"] += r["amount"]
        if o["refunded_total"] >= o["paid_amount"]:
            o["status"] = "refunded"
        return r

    # ---------------- admin ----------------
    @app.get("/coupons", tags=["admin"], operation_id="list_coupons")
    def list_coupons(u=Depends(auth)):
        if u["role"] != "merchant_admin":
            raise HTTPException(403, "merchant_admin only")
        return [c for c in rng.db["coupons"].values() if c["tenant"] == u["tenant"]]

    @app.post("/coupons", tags=["admin"], operation_id="create_coupon", status_code=201)
    def create_coupon(b: CouponCreate, u=Depends(auth)):
        if u["role"] != "merchant_admin":
            raise HTTPException(403, "merchant_admin only")
        code = b.code.upper()
        if code in rng.db["coupons"]:
            raise HTTPException(409, "code exists")
        c = {"code": code, "tenant": u["tenant"], "percent": b.percent, "max_uses": b.max_uses, "uses": 0}
        rng.db["coupons"][code] = c
        return c

    @app.get("/reports/sales", tags=["admin"], operation_id="sales_report")
    def sales_report(u=Depends(auth)):
        if not (u["role"] == "merchant_admin" or V("SF-08")):                    # SF-08
            raise HTTPException(403, "merchant_admin only")
        os_ = [o for o in rng.db["orders"].values() if o["tenant"] == u["tenant"]
               and o["status"] in LIVE + ("refunded",)]
        return {"tenant": u["tenant"], "orders": len(os_), "gross": sum(o["paid_amount"] for o in os_)}

    return app


app = create_app(enabled_from_env(FLAWS))
