"""Generate immutable, per-target allowlists from normalized OpenAPI and config.

OpenAPI establishes which operations are documented; it does not establish
roles, ownership, business rules, or permission to execute destructive writes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import yaml

from src.spec.loader import load_spec


class AllowlistBuildError(ValueError):
    """Target configuration is incomplete or unsafe."""


def _operations(spec: Any) -> list[dict[str, Any]]:
    normalized = spec.to_dict() if hasattr(spec, "to_dict") else spec
    items = normalized.get("operations", [])
    result = []
    for item in items:
        method = str(item["method"]).upper()
        # Unknown/destructive operations are not enabled by spec presence.
        result.append({
            "id": item["operation_id"],
            "operation_id": item["operation_id"],
            "method": method,
            "path": item.get("route_template", item.get("path")),
            "documented": True,
            "allow": True,
            "destructiveness": "unknown",
            "tags": [],
            "source": "openapi",
        })
    return sorted(result, key=lambda row: (row["path"], row["method"], row["id"]))


def build_allowlist(spec: Any, config: Mapping[str, Any]) -> dict[str, Any]:
    """Build a target-scoped allowlist; explicit config never mutates the spec."""
    target = config.get("target") or {}
    target_id = config.get("target_id") or target.get("id")
    base_url = target.get("base_url")
    scope = config.get("scope") or {}
    hosts = scope.get("in_scope_hosts") or []
    undocumented_policy = config.get("undocumented_policy")
    if not isinstance(target_id, str) or not target_id.strip():
        raise AllowlistBuildError("target_id is required")
    if not isinstance(base_url, str) or not base_url.strip():
        raise AllowlistBuildError("target.base_url is required")
    if not isinstance(hosts, list) or not hosts or not all(isinstance(h, str) and h for h in hosts):
        raise AllowlistBuildError("scope.in_scope_hosts must explicitly list host[:port] values")
    if undocumented_policy not in {"block", "hold", "allow_and_flag"}:
        raise AllowlistBuildError("undocumented_policy is required: block | hold | allow_and_flag")

    entries = _operations(spec)
    overrides = config.get("operation_overrides") or {}
    if not isinstance(overrides, dict):
        raise AllowlistBuildError("operation_overrides must be a mapping keyed by operation_id")
    for entry in entries:
        override = overrides.get(
            entry["operation_id"],
            overrides.get("{} {}".format(entry["method"], entry["path"]), {}),
        )
        if not isinstance(override, dict):
            raise AllowlistBuildError(f"override for {entry['operation_id']} must be a mapping")
        if "allow" in override:
            if not isinstance(override["allow"], bool):
                raise AllowlistBuildError(f"allow override for {entry['operation_id']} must be boolean")
            entry["allow"] = override["allow"]
        entry["tags"] = list(override.get("tags", []))
        entry["destructiveness"] = override.get("destructiveness", "unknown")

    payload = {
        "schema_version": 1,
        "target_id": target_id,
        "target": {"base_url": base_url},
        "scope": {
            "in_scope_hosts": list(hosts),
            "out_of_scope_default": "block",
            "pass_hosts": list(scope.get("pass_hosts", [])),
        },
        "undocumented_policy": undocumented_policy,
        "approved_patterns": list(config.get("approved_patterns", [])),
        "extra_methods": list(config.get("extra_methods", [])),
        "budgets": dict(config.get("budgets", {})),
        "destructiveness": dict(config.get("destructiveness", {})),
        "entries": entries,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    payload["allowlist_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openapi", required=True, help="Path to this target's OpenAPI JSON/YAML")
    parser.add_argument("--config", required=True, help="Path to config/<target>/gateway.yaml")
    parser.add_argument("--output", required=True, help="Run-scoped allowlist.generated.json destination")
    args = parser.parse_args()
    spec = load_spec(args.openapi)
    config = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise AllowlistBuildError("gateway config must be a YAML mapping")
    generated = build_allowlist(spec, config)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(generated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Generated {len(generated['entries'])} operations for {generated['target_id']} at {output}")


if __name__ == "__main__":
    main()
