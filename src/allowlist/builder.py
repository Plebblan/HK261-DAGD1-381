"""Build the gateway's route allowlist from the app's OpenAPI document.

The allowlist is deliberately only an execution boundary: it contains route
templates and HTTP methods. It does not encode expected responses or oracle data.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}
ROOT = Path(__file__).resolve().parent


def operations(spec: dict[str, Any]) -> list[dict[str, Any]]:
    entries = []
    for path, path_item in spec.get("paths", {}).items():
        for method, operation in path_item.items():
            if method.lower() not in METHODS or not isinstance(operation, dict):
                continue
            operation_id = operation.get("operationId") or f"{method.upper()}_{path}"
            entries.append({
                "id": operation_id,
                "method": method.upper(),
                "path": path,
                "host": "localhost:8000",
                "allow": True,
                "auth_required": path not in {"/health", "/__lab/auth/token"},
            })
    return sorted(entries, key=lambda item: (item["path"], item["method"], item["id"]))


def build(spec: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": 1,
        "purpose": "Gateway route boundary generated from the app OpenAPI contract.",
        "target": {"scheme": "http", "host": "localhost", "port": 8000,
                   "base_url": "http://localhost:8000"},
        "default_deny": True,
        "allow_external_hosts": False,
        "global_limits": {"max_concurrency": 2, "timeout_seconds": 10,
                          "max_requests_per_run": 40},
        "entries": operations(spec),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openapi", default=str(ROOT.parent / "docs/openapi.json"))
    parser.add_argument("--output", default=str(ROOT / "runtrace_allowlist.json"))
    args = parser.parse_args()
    spec = json.loads(Path(args.openapi).read_text(encoding="utf-8"))
    result = build(spec)
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Built {len(result['entries'])} allowlist entries from {args.openapi} -> {args.output}")


if __name__ == "__main__":
    main()
