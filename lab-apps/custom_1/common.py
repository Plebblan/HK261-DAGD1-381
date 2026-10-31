"""Shared plumbing for the synthetic Cyber Range apps.

Design goals (map to Phase-1 KPIs):
  * Fixed seed + atomic reset  -> reproducibility across seeds / state-reset cost
  * Every planted flaw is a named switch (e.g. "TD-04") -> ground truth + benign corpus
  * Every authenticated request lands in an audit log   -> provenance / evidence
All users, tokens and data are synthetic. Bind to 127.0.0.1 only.
"""
import json
import os
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

SEED = int(os.getenv("RANGE_SEED", "1337"))
LAB_KEY = os.getenv("LAB_KEY", "lab-only-synthetic-key")
bearer = HTTPBearer(auto_error=False)


def use_openapi_file(app: FastAPI, path: Path):
    spec = json.loads(path.read_text(encoding="utf-8"))
    app.openapi = lambda: spec


def enabled_from_env(all_flaws):
    """ENABLED_FLAWS=ALL | NONE | TD-01,TD-04 ..."""
    raw = os.getenv("ENABLED_FLAWS", "ALL").strip()
    if raw.upper() == "ALL":
        return set(all_flaws)
    if raw.upper() in ("NONE", ""):
        return set()
    return {x.strip() for x in raw.split(",") if x.strip()}


class Range:
    def __init__(self, name, seed_fn, all_flaws, enabled=None):
        self.name = name
        self._seed = seed_fn
        self.all_flaws = set(all_flaws)
        self.enabled = set(all_flaws) if enabled is None else set(enabled) & self.all_flaws
        self.reset()

    def reset(self):
        self.db = self._seed()
        self.db["sessions"] = {}
        self.audit = []

    def vuln(self, flaw_id):
        assert flaw_id in self.all_flaws, f"unknown flaw {flaw_id}"
        return flaw_id in self.enabled

    def next_id(self, kind):
        self.db["seq"][kind] = self.db["seq"].get(kind, 0) + 1
        return self.db["seq"][kind]

    def login(self, user):
        tok = f"tok_{user['username']}_{SEED}_{self.next_id('session')}"
        self.db["sessions"][tok] = user["id"]
        return tok


def make_auth(rng):
    def dep(request: Request, cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
        if cred is None:
            raise HTTPException(401, "missing bearer token")
        uid = rng.db["sessions"].get(cred.credentials)
        if uid is None or uid not in rng.db["users"]:
            raise HTTPException(401, "invalid or expired token")
        u = rng.db["users"][uid]
        rng.audit.append({"tenant": u["tenant"], "actor": u["username"],
                          "method": request.method, "path": request.url.path})
        return {**u, "_token": cred.credentials}
    return dep


def add_lab_routes(app: FastAPI, rng: Range):
    """Control plane for the harness. Hidden from the target OpenAPI spec."""
    def chk(key):
        if key != LAB_KEY:
            raise HTTPException(403, "lab key required")

    @app.get("/_lab/health", include_in_schema=False)
    def health():
        return {"app": rng.name, "seed": SEED, "enabled_flaws": sorted(rng.enabled)}

    @app.post("/_lab/reset", include_in_schema=False)
    def lab_reset(x_lab_key: Optional[str] = Header(default=None)):
        chk(x_lab_key)
        rng.reset()
        return {"status": "reset", "seed": SEED, "enabled_flaws": sorted(rng.enabled)}

    @app.get("/_lab/state", include_in_schema=False)
    def lab_state(x_lab_key: Optional[str] = Header(default=None)):
        chk(x_lab_key)  # full state snapshot -> before/after evidence
        return {"db": rng.db}

    @app.get("/_lab/audit", include_in_schema=False)
    def lab_audit(x_lab_key: Optional[str] = Header(default=None)):
        chk(x_lab_key)
        return {"audit": rng.audit}
