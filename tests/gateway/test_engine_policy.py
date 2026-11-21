from src.common.types import GatewayRequest
from src.gateway.engine import decide, match_path_template


def sample_allowlist():
    return {
        "scope": {"in_scope_hosts": ["127.0.0.1:8001"], "pass_hosts": []},
        "undocumented_policy": "block",
        "approved_patterns": [{"method": "POST", "path": "/customers", "actor": "tester"}],
        "destructiveness": {"enabled_tags": ["read", "create"], "disabled_tags": ["unknown", "terminal"]},
        "entries": [
            {"id": "list", "method": "GET", "path": "/customers", "allow": True, "destructiveness": "read"},
            {"id": "create", "method": "POST", "path": "/customers", "allow": True, "destructiveness": "unknown"},
            {"id": "one", "method": "GET", "path": "/customers/{id}", "allow": True, "destructiveness": "read"},
        ],
    }


def test_openapi_template_matches_single_segment_only():
    assert match_path_template("/customers/{id}", "/customers/123")
    assert not match_path_template("/customers/{id}", "/customers/123/orders")


def test_documented_get_is_forwarded():
    verdict = decide(GatewayRequest(method="GET", host="127.0.0.1:8001", path="/customers"),
                     allowlist=sample_allowlist())
    assert verdict.action == "forwarded"


def test_write_requires_approved_pattern():
    verdict = decide(GatewayRequest(method="POST", host="127.0.0.1:8001", path="/customers", actor="other", headers={"x-range-approval": "true"}),
                     allowlist=sample_allowlist())
    assert verdict.action == "blocked"
    assert verdict.reason == "write_requires_approval"


def test_approved_write_is_forwarded():
    verdict = decide(GatewayRequest(method="POST", host="127.0.0.1:8001", path="/customers", actor="tester", headers={"x-range-approval": "true"}),
                     allowlist=sample_allowlist())
    assert verdict.action == "forwarded"


def test_undocumented_operation_is_blocked():
    verdict = decide(GatewayRequest(method="DELETE", host="127.0.0.1:8001", path="/customers/1"),
                     allowlist=sample_allowlist())
    assert verdict.action == "blocked"
    assert verdict.reason == "undocumented_operation"


def test_out_of_scope_host_is_blocked():
    verdict = decide(GatewayRequest(method="GET", host="example.com", path="/customers"),
                     allowlist=sample_allowlist())
    assert verdict.reason == "out_of_scope_host"


def test_missing_allowlist_fails_closed():
    assert decide(GatewayRequest(method="GET", host="127.0.0.1:8001", path="/customers")).action == "blocked"


def test_wildcard_approval_pattern_still_requires_request_signal():
    allowlist = sample_allowlist()
    allowlist["approved_patterns"] = [{"method": "*", "path": "*"}]
    request = GatewayRequest(
        method="DELETE", host="127.0.0.1:8001", path="/customers/1",
        actor="tester", headers={"x-range-approval": "true"},
    )
    # An undocumented path remains blocked even when the approval signal is present.
    assert decide(request, allowlist=allowlist).reason == "undocumented_operation"
