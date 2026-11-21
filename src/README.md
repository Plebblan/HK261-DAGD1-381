# Source tree

This directory contains the implementation scaffold for the gateway tool described in `docs/Workflows/Architecture.md`.

The package is organized by responsibility:

- `common/` for dependency-free shared utilities
- `store/` for the SQLite adapter
- `spec/` for OpenAPI loading and analysis
- `allowlist/` for generated allowlists
- `gateway/` for the pure policy engine
- `proxy/` for the mitmproxy adapter
- `restoration/` for optional reset logic
- `control/` for the API and review UI
- `capture/`, `inference/`, `planting/`, `model/`, `probes/`, `oracle/` for later phases

This is intentionally a first-iteration skeleton; modules are created in the architecture order and keep stable import boundaries for the rest of the implementation.
