"""Shared helpers for the custom_1 harness scripts (run_trace.py, coverage.py): RSO route matching and object ids."""
import json, re
from pathlib import Path

HERE = Path(__file__).resolve().parent

# path parameter -> seed object type (object ids look like "<type>-<value>", e.g. ticket-1002, user-3)
PARAM_TYPE = {"ticket_id": "ticket", "doc_id": "document", "user_id": "user", "order_id": "order",
              "product_id": "product", "refund_id": "refund"}


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


class Routes:
    """Match (app, method, concrete path) to an RSO action and the object it addresses."""

    def __init__(self, rso):
        self.by_app = {}
        for a in rso["actions"]:
            rx = "^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", a["path"]) + "$"
            self.by_app.setdefault(a["App"], []).append((a["method"], re.compile(rx), a))

    def match(self, app, method, path):
        path = path.split("?")[0]
        for m, rx, a in self.by_app.get(app, []):
            hit = rx.match(path)
            if m == method.upper() and hit:
                return a, hit.groupdict()
        return None, {}

    @staticmethod
    def object_id(params):
        for p, t in PARAM_TYPE.items():
            if p in params:
                return f"{t}-{params[p]}"
        return None
