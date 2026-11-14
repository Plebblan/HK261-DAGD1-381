#!/usr/bin/env python3
"""Start the existing Safety Gateway engine (lab-apps/custom/app/gateway.py) for a custom_1 app.

    python custom_1/cyber-range/gateway/start_gateway.py tenantdesk     # listens on 127.0.0.1:8101 -> localhost:8001
    python custom_1/cyber-range/gateway/start_gateway.py shopflow       # listens on 127.0.0.1:8102 -> localhost:8002

The engine is reused unchanged; only the per-app profile and allowlist in this folder differ. Run it on the host
(the engine refuses to bind to anything but loopback), next to the docker-published app ports.
Needs fastapi, uvicorn and httpx (custom/requirements.txt).
"""
import os, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB_APPS = HERE.parents[2]                      # lab-apps/
ENGINE_DIR = LAB_APPS / "custom" / "app"

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("tenantdesk", "shopflow"):
        sys.exit(__doc__)
    app = sys.argv[1]
    os.chdir(LAB_APPS)                          # profile paths are relative to lab-apps/
    sys.path.insert(0, str(ENGINE_DIR))
    import gateway                              # the existing engine, unmodified
    sys.argv = ["gateway.py", "--serve", "--profile", str(HERE / f"{app}_profile.json")]
    gateway.main()
