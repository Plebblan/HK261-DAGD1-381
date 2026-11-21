from src.allowlist.builder import AllowlistBuildError, build_allowlist


def test_builds_target_specific_allowlist_with_safe_write_defaults():
    spec = {
        "operations": [
            {"operation_id": "listUsers", "method": "GET", "route_template": "/users"},
            {"operation_id": "deleteUser", "method": "DELETE", "route_template": "/users/{id}"},
        ]
    }
    config = {
        "target_id": "tenantdesk",
        "target": {"base_url": "http://127.0.0.1:8001"},
        "scope": {"in_scope_hosts": ["127.0.0.1:8001"]},
        "undocumented_policy": "block",
    }
    result = build_allowlist(spec, config)
    assert result["target_id"] == "tenantdesk"
    assert result["entries"][0]["allow"] is True
    assert result["entries"][1]["allow"] is True
    assert result["entries"][1]["destructiveness"] == "unknown"
    assert result["allowlist_hash"]


def test_builder_requires_explicit_undocumented_policy():
    spec = {"operations": []}
    config = {"target_id": "x", "target": {"base_url": "http://127.0.0.1:8000"},
              "scope": {"in_scope_hosts": ["127.0.0.1:8000"]}}
    try:
        build_allowlist(spec, config)
    except AllowlistBuildError as exc:
        assert "undocumented_policy" in str(exc)
    else:
        raise AssertionError("expected config validation error")


def test_operation_override_can_disable_documented_operation():
    spec = {"operations": [{"operation_id": "listUsers", "method": "GET", "route_template": "/users"}]}
    config = {"target_id": "x", "target": {"base_url": "http://127.0.0.1:8000"},
              "scope": {"in_scope_hosts": ["127.0.0.1:8000"]}, "undocumented_policy": "block",
              "operation_overrides": {"listUsers": {"allow": False}}}
    assert build_allowlist(spec, config)["entries"][0]["allow"] is False


def test_operation_override_can_target_method_and_route():
    spec = {"operations": [{"operation_id": "login", "method": "POST", "route_template": "/auth/login"}]}
    config = {
        "target_id": "tenantdesk",
        "target": {"base_url": "http://127.0.0.1:8001"},
        "scope": {"in_scope_hosts": ["127.0.0.1:8001"]},
        "undocumented_policy": "block",
        "operation_overrides": {"POST /auth/login": {"destructiveness": "create", "tags": ["auth"]}},
    }
    entry = build_allowlist(spec, config)["entries"][0]
    assert entry["destructiveness"] == "create"
    assert entry["tags"] == ["auth"]
