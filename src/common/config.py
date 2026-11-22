"""Load and validate target-specific gateway YAML configuration."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_config(path: str | Path) -> dict[str, Any]:
    """Load a YAML mapping from a target's gateway.yaml."""
    config_path = Path(path)
    if not config_path.is_file():
        raise FileNotFoundError(f"Config not found: {config_path}")
    try:
        value = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Cannot load gateway config {config_path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("Gateway config root must be a YAML mapping")
    validate_config(value)
    return value


def validate_config(config: dict[str, Any]) -> None:
    """Fail closed when the target scope or shadow-API policy is unspecified."""
    target = config.get("target") or {}
    if not config.get("target_id"):
        raise ValueError("target_id is required")
    if not isinstance(target.get("base_url"), str) or not target["base_url"]:
        raise ValueError("target.base_url is required")
    scope = config.get("scope") or {}
    hosts = scope.get("in_scope_hosts")
    if not isinstance(hosts, list) or not hosts or not all(isinstance(host, str) and host for host in hosts):
        raise ValueError("scope.in_scope_hosts must be a non-empty list")
    if config.get("undocumented_policy") not in {"block", "hold", "allow_and_flag"}:
        raise ValueError("undocumented_policy is required: block | hold | allow_and_flag")
    pass_hosts = scope.get("pass_hosts", [])
    if not isinstance(pass_hosts, list) or not all(isinstance(host, str) and host for host in pass_hosts):
        raise ValueError("scope.pass_hosts must be a list of exact host[:port] values")
