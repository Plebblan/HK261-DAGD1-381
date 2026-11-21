#!/usr/bin/env python3
"""Start the shared OpenAPI-driven reverse proxy for TenantDesk or ShopFlow.

Generate the run-scoped allowlist first, then start one proxy process per run:

  python lab-apps/custom_1/cyber-range/gateway/start_gateway.py tenantdesk \
    --run-id "$RUN_ID" --run-dir "runs/tenantdesk/$RUN_ID" \
    --allowlist "runs/tenantdesk/$RUN_ID/allowlist.generated.json" \
    --openapi "runs/tenantdesk/$RUN_ID/openapi.json"

The listener ports remain compatible with run_trace.py: 8101 (TenantDesk),
8102 (ShopFlow). No legacy gateway code or app-specific policy engine is used.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", choices=("tenantdesk", "shopflow"))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--allowlist", required=True)
    parser.add_argument("--openapi")
    parser.add_argument("--config")
    args = parser.parse_args()

    port = 8101 if args.app == "tenantdesk" else 8102
    config = Path(args.config or ROOT / "config" / args.app / "gateway.yaml")
    command = [
        sys.executable, "-m", "src.proxy.run",
        "--allowlist", str(Path(args.allowlist).resolve()),
        "--config", str(config.resolve()),
        "--run-dir", str(Path(args.run_dir).resolve()),
        "--run-id", args.run_id,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(port),
    ]
    if args.openapi:
        command.extend(["--openapi", str(Path(args.openapi).resolve())])
    raise SystemExit(subprocess.call(command, cwd=ROOT))


if __name__ == "__main__":
    main()
