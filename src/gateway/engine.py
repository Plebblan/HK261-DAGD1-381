"""Transport-independent Safety Gateway policy decision function."""
from __future__ import annotations

import re
from typing import Any, Mapping

from src.common.types import GatewayRequest, VerdictRecord


def canonical_path(path: str) -> str:
    """Normalize URL path shape while rejecting traversal."""
    value = "/" + str(path).split("?", 1)[0].strip("/")
    if chr(92) in value:
        raise ValueError("invalid request path")
    if any(segment in {".", ".."} for segment in value.split("/")):
        raise ValueError("path traversal is not allowed")
    return value or "/"


def match_path_template(template: str, actual: str) -> bool:
    """Match OpenAPI parameter segments without crossing path separators."""
    expected = canonical_path(template).split("/")
    received = canonical_path(actual).split("/")
    if len(expected) != len(received):
        return False
    for expected_segment, actual_segment in zip(expected, received):
        if expected_segment.startswith("{") and expected_segment.endswith("}") and len(expected_segment) > 2:
            if not actual_segment:
                return False
        elif expected_segment != actual_segment:
            return False
    return True


def _host(value: str) -> str:
    return str(value).strip().lower().rstrip(".")


def _host_matches(request_host: str, configured_host: str) -> bool:
    return _host(request_host) == _host(configured_host)


def _approved(request: GatewayRequest, patterns: list[dict[str, Any]]) -> bool:
    for pattern in patterns:
        if not isinstance(pattern, dict):
            continue
        pattern_method = str(pattern.get("method", "")).upper()
        if pattern_method not in {"*", request.method.upper()}:
            continue
        pattern_path = str(pattern.get("path", ""))
        if pattern_path != "*" and not match_path_template(pattern_path, request.path):
            continue
        actor = pattern.get("actor")
        if actor is not None and actor != request.actor:
            continue
        if pattern.get("host") and not _host_matches(request.host, str(pattern["host"])):
            continue
        return True
    return False


def decide(
    request: GatewayRequest,
    *,
    allowlist: Mapping[str, Any] | list[dict[str, Any]] | None = None,
    config: Mapping[str, Any] | None = None,
) -> VerdictRecord:
    """Evaluate one outbound request; performs no network I/O."""
    if not isinstance(allowlist, (dict, list)):
        return VerdictRecord(action="blocked", reason="missing_allowlist")
    data: Mapping[str, Any] = {"entries": allowlist} if isinstance(allowlist, list) else allowlist
    cfg = config or {}
    method = request.method.upper()
    try:
        path = canonical_path(request.path)
    except ValueError:
        return VerdictRecord(action="blocked", reason="invalid_path")

    if bool(cfg.get("kill_switch", False)):
        return VerdictRecord(action="blocked", reason="kill_switch")

    scope = data.get("scope", cfg.get("scope", {})) or {}
    in_scope = scope.get("in_scope_hosts", [])
    pass_hosts = scope.get("pass_hosts", [])
    if not any(_host_matches(request.host, str(host)) for host in in_scope):
        if any(_host_matches(request.host, str(host)) for host in pass_hosts):
            return VerdictRecord(action="tunneled", reason="explicit_pass_host")
        return VerdictRecord(action="blocked", reason="out_of_scope_host")

    matched = None
    for entry in data.get("entries", []):
        if (str(entry.get("method", "")).upper() == method
                and match_path_template(str(entry.get("path", "")), path)):
            matched = entry
            break

    if matched is None:
        for extra in data.get("extra_methods", []):
            if (str(extra.get("method", "")).upper() == method
                    and match_path_template(str(extra.get("path", "")), path)
                    and (not extra.get("host") or _host_matches(request.host, str(extra["host"])))):
                matched = {
                    "id": extra.get("id", "extra_method"),
                    "method": method,
                    "path": extra.get("path"),
                    "allow": True,
                    "destructiveness": extra.get("destructiveness", "unknown"),
                    "tags": ["extra_method"],
                    "source": "config",
                }
                break

    approved_patterns = list(data.get("approved_patterns", cfg.get("approved_patterns", [])))
    # A configured pattern defines which operation may be manually approved;
    # the per-request header is the explicit approval signal from RunTrace.
    approval_signal = str(request.headers.get("x-range-approval", "")).lower() == "true"
    approved = approval_signal and _approved(request, approved_patterns)
    if matched is None:
        policy = data.get("undocumented_policy", cfg.get("undocumented_policy"))
        if policy == "allow_and_flag":
            return VerdictRecord(action="forwarded", reason="undocumented_allow_and_flag",
                                 tags=("undocumented",))
        if policy == "hold" and approved:
            return VerdictRecord(action="forwarded", reason="pre_approved_undocumented",
                                 allowlist_rule="approved_pattern", tags=("undocumented",))
        return VerdictRecord(action="blocked", reason="undocumented_operation")

    if matched.get("allow") is False:
        return VerdictRecord(action="blocked", reason="operation_disabled",
                             allowlist_rule=matched.get("id"))

    destructiveness = matched.get("destructiveness", "unknown")
    policy = data.get("destructiveness") or cfg.get("destructiveness") or {}
    enabled = set(policy.get("enabled_tags", ["read"]))
    disabled = set(policy.get("disabled_tags", ["terminal", "session_affecting", "unknown"]))
    tags = tuple(matched.get("tags", []))
    if method not in {"GET", "HEAD", "OPTIONS"} and not approved:
        if destructiveness == "unknown" or destructiveness in disabled or destructiveness not in enabled:
            return VerdictRecord(action="blocked", reason="write_requires_approval",
                                 allowlist_rule=matched.get("id"), tags=tags)

    if cfg.get("dry_run", data.get("dry_run", False)):
        return VerdictRecord(action="dry_run", reason="policy_permitted",
                             allowlist_rule=matched.get("id"), tags=tags)
    return VerdictRecord(action="forwarded", reason="allowlisted_operation",
                         allowlist_rule=matched.get("id"), tags=tags)
