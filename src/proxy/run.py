"""Launch the shared Safety Gateway as a target-specific reverse proxy."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import yaml


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allowlist", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--openapi")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=8088)
    args = parser.parse_args()

    if args.listen_host not in {"127.0.0.1", "::1", "localhost"}:
        parser.error("gateway listener must bind to loopback")
    config = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not isinstance(config.get("target"), dict):
        parser.error("gateway config must contain target.base_url")
    upstream = config["target"].get("base_url")
    if not isinstance(upstream, str) or not upstream.startswith(("http://127.0.0.1:", "http://localhost:", "http://[::1]:")):
        parser.error("only explicitly configured loopback HTTP lab targets are supported")

    addon = Path(__file__).with_name("addon.py").resolve()
    command = [
        "mitmdump",
        "--mode", f"reverse:{upstream}",
        "--listen-host", args.listen_host,
        "--listen-port", str(args.listen_port),
        "-s", str(addon),
        "--set", f"gateway_allowlist={Path(args.allowlist).resolve()}",
        "--set", f"gateway_config={Path(args.config).resolve()}",
        "--set", f"gateway_run_dir={Path(args.run_dir).resolve()}",
        "--set", f"gateway_run_id={args.run_id}",
        "--set", f"gateway_openapi={Path(args.openapi).resolve()}" if args.openapi else "gateway_openapi=",
    ]
    print("Starting shared reverse proxy:", " ".join(command), flush=True)
    raise SystemExit(subprocess.call(command))


if __name__ == "__main__":
    main()
