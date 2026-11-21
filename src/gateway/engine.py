<<<<<<< Updated upstream
"""Policy engine implementing gateway decision-making."""

from __future__ import annotations

from typing import Any

from src.common.types import GatewayRequest, VerdictRecord


def decide(request: GatewayRequest, *, allowlist: list[dict[str, Any]] | None = None) -> VerdictRecord:
    """Return a gateway verdict for a request.

    This first iteration intentionally defaults to allowing requests unless the
    caller explicitly asks for a stricter decision policy.
    """
    _ = allowlist
    return VerdictRecord(action="allow", reason="default allow policy", tags=())
=======
"""Gateway policy engine (Architecture.md sections 2 and 3).

``decide(request, policy, counters)`` is a pure function: it forwards nothing,
touches no network and keeps no state. The proxy adapter applies the verdict.
Everything is default-deny; the only ways a request is forwarded are

* a match against the generated allowlist (spec entries or config ``extra_methods``),
* in capture mode only: a static-asset GET under an explicit path prefix, or an
  undocumented request admitted by ``undocumented_policy`` (``hold`` needs a
  pre-approved pattern, ``allow_and_flag`` flags it).

Order of checks: kill switch, audit health, host scope, path sanity, allowlist
match / undocumented handling, destructiveness gate, budgets, dry-run.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from src.allowlist.builder import AllowlistError, compute_allowlist_hash, load_allowlist
from src.common.config import DESTRUCTIVENESS_TAGS, load_config, validate_config
from src.common.types import GatewayRequest, Verdict

from .budgets import BudgetLimits, BudgetTracker, Counters, check_budgets
from .kill_switch import KillSwitch
from .rules import SAFE_METHODS, CompiledTemplate, MalformedPath, compile_template, host_key, split_path


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    operation_id: str | None
    template: CompiledTemplate


@dataclass(frozen=True)
class _Approved:
    index: int
    method: str
    template: CompiledTemplate
    actor: str | None


class Policy:
    """Immutable, pre-compiled view of (allowlist, config) used by ``decide``."""

    def __init__(
        self,
        allowlist: Mapping[str, Any],
        config: Mapping[str, Any],
        *,
        operation_tags: Mapping[str, str] | None = None,
    ):
        config = validate_config(config)
        if allowlist.get("allowlist_hash") != compute_allowlist_hash(allowlist):
            raise AllowlistError("allowlist hash mismatch: refusing to use a modified allowlist")
        if list(allowlist.get("in_scope_hosts", [])) != config["scope"]["in_scope_hosts"]:
            raise AllowlistError("allowlist was generated for a different scope.in_scope_hosts")
        expected = sorted((e["method"], e["host"], e["path"]) for e in config["extra_methods"])
        actual = sorted((e["method"], e["host"], e["path_template"]) for e in allowlist.get("config_entries", []))
        if expected != actual:
            raise AllowlistError("allowlist config entries do not match config extra_methods; regenerate it")
        tags = dict(operation_tags or {})
        if not set(tags.values()) <= set(DESTRUCTIVENESS_TAGS):
            raise ValueError("operation_tags contain an unknown destructiveness tag")

        self.allowlist_hash: str = allowlist["allowlist_hash"]
        self.in_scope = frozenset(config["scope"]["in_scope_hosts"])
        self.pass_hosts = frozenset(config["scope"]["pass_hosts"])
        self.static_prefixes = tuple(config["scope"]["static_path_prefixes"])
        self.undocumented_policy: str = config["undocumented_policy"]
        self.dry_run: bool = config["dry_run"]
        self.enabled_tags = frozenset(config["destructiveness"]["enabled_tags"])
        self.disabled_tags = frozenset(config["destructiveness"]["disabled_tags"])
        self.overrides = dict(config["destructiveness"]["per_operation_override"])
        self.operation_tags = tags
        self.limits = BudgetLimits.from_config(config)
        self.approved = tuple(
            _Approved(i, p["method"], compile_template(p["path"]), p.get("actor"))
            for i, p in enumerate(config["approved_patterns"])
        )
        index: dict[tuple[str, str], list[_Rule]] = {}
        for entry in (*allowlist.get("spec_entries", []), *allowlist.get("config_entries", [])):
            rule = _Rule(entry["rule_id"], entry.get("operation_id"), compile_template(entry["path_template"]))
            index.setdefault((entry["host"], entry["method"].upper()), []).append(rule)
        # most specific template first (more literal segments), deterministic tie-break
        self._rules = {
            key: tuple(sorted(rules, key=lambda r: (-r.template.literal_count, r.rule_id)))
            for key, rules in index.items()
        }

    @classmethod
    def from_files(cls, allowlist_path: str | Path, config_path: str | Path, **kwargs: Any) -> "Policy":
        return cls(load_allowlist(allowlist_path), load_config(config_path), **kwargs)

    def match(self, host: str, method: str, segments: tuple[str, ...]) -> _Rule | None:
        for rule in self._rules.get((host, method), ()):
            if rule.template.matches(segments):
                return rule
        return None

    def approved_match(self, method: str, actor: str | None, segments: tuple[str, ...]) -> _Approved | None:
        for pattern in self.approved:
            if pattern.method == method and (pattern.actor is None or pattern.actor == actor) \
                    and pattern.template.matches(segments):
                return pattern
        return None


def _gate(policy: Policy, method: str, actor: str | None, segments: tuple[str, ...], rule: _Rule | None) -> str | None:
    """Destructiveness approval gate. Returns a block reason, or None to pass."""
    operation_id = rule.operation_id if rule else None
    override = policy.overrides.get(operation_id) if operation_id else None
    if override == "disabled":
        return "destructive_disabled"
    if override == "enabled":
        return None
    tag = policy.operation_tags.get(operation_id) if operation_id else None
    if tag is not None:
        if tag in policy.disabled_tags or tag not in policy.enabled_tags:
            return "destructive_disabled"
        return None
    # No tag yet: reads pass; writes only if they match a pre-approved pattern.
    if method in SAFE_METHODS or policy.approved_match(method, actor, segments):
        return None
    return "destructive_unapproved"


def decide(
    request: GatewayRequest,
    policy: Policy,
    counters: Counters | None = None,
    *,
    kill_switch: bool = False,
) -> Verdict:
    """Return the gateway verdict for one outbound request."""
    counters = counters or Counters()
    method = request.method.strip().upper()

    def verdict(decision: str, reason: str, rule_id: str | None = None, **extra: Any) -> Verdict:
        return Verdict(decision, reason, rule_id, policy.allowlist_hash, **extra)  # type: ignore[arg-type]

    if kill_switch:
        return verdict("blocked", "kill_switch")
    if not counters.writer_healthy:
        return verdict("blocked", "audit_unavailable")          # fail closed
    if request.mode not in ("capture", "test"):
        return verdict("blocked", "invalid_mode")

    key = host_key(request.host, request.port)
    if key not in policy.in_scope:
        if key in policy.pass_hosts:                            # explicit host, tunneled uninspected
            if policy.dry_run:
                return verdict("dry_run", "dry_run", f"pass_host:{key}", flags=("would_tunnel",), detail="pass_host")
            return verdict("tunneled", "pass_host", f"pass_host:{key}")
        return verdict("blocked", "out_of_scope_host")

    try:
        segments = split_path(request.path)
    except MalformedPath:
        return verdict("blocked", "malformed_path")

    rule = policy.match(key, method, segments)
    flags: tuple[str, ...] = ()
    rule_id: str | None
    if rule is not None:
        rule_id, operation_id, reason = rule.rule_id, rule.operation_id, "allowlisted"
    else:
        operation_id = None
        if request.mode == "test":                              # strict spec-derived allowlist
            return verdict("blocked", "not_in_allowlist")
        joined = "/" + "/".join(segments) + ("/" if segments else "")
        prefix = next((p for p in policy.static_prefixes if joined.startswith(p)), None)
        if method == "GET" and prefix is not None:
            rule_id, reason, flags = f"static:{prefix}", "static", ("static",)
        elif policy.undocumented_policy == "block":
            return verdict("blocked", "undocumented_path", flags=("undocumented",))
        elif policy.undocumented_policy == "hold":
            approved = policy.approved_match(method, request.actor, segments)
            if approved is None:
                return verdict("blocked", "undocumented_path", flags=("undocumented",))
            rule_id, reason, flags = f"approved:{approved.index}", "pre_approved", ("undocumented",)
        else:                                                   # allow_and_flag
            rule_id, reason, flags = None, "allow_and_flag", ("undocumented",)

    blocked_by_gate = _gate(policy, method, request.actor, segments, rule)
    if blocked_by_gate:
        return verdict("blocked", blocked_by_gate, rule_id, operation_id=operation_id, flags=flags)

    budget = check_budgets(policy.limits, counters)
    if not budget.ok:
        if budget.detail == "audit_unavailable":
            return verdict("blocked", "audit_unavailable", rule_id, operation_id=operation_id, flags=flags)
        return verdict("blocked", "budget_exceeded", rule_id, operation_id=operation_id, flags=flags,
                       detail=budget.detail, retry_after_s=budget.retry_after_s)

    if policy.dry_run:
        return verdict("dry_run", "dry_run", rule_id, operation_id=operation_id,
                       flags=(*flags, "would_forward"), detail=reason)
    return verdict("forwarded", reason, rule_id, operation_id=operation_id, flags=flags)


class Gateway:
    """Stateful wrapper: snapshots counters, decides, and reserves budget atomically.

    ``decide`` stays pure; this class only owns the mutable counters and the kill
    switch. The proxy adapter calls :meth:`evaluate` before forwarding and
    :meth:`complete` once the upstream response has been handled.
    """

    def __init__(
        self,
        policy: Policy,
        *,
        kill_switch: KillSwitch | None = None,
        tracker: BudgetTracker | None = None,
        writer_health: Callable[[], Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.policy = policy
        self.kill_switch = kill_switch or KillSwitch()
        self.tracker = tracker or BudgetTracker()
        self._writer_health = writer_health
        self._sleep, self._clock = sleep, clock

    def _writer_state(self) -> tuple[float, bool]:
        if self._writer_health is None:
            return 0.0, True
        health = self._writer_health()
        return float(health.pressure), health.state != "degraded"

    def evaluate(self, request: GatewayRequest, *, max_wait_s: float = 0.0) -> Verdict:
        """Decide, reserving budget when the request will be sent.

        Transient budget blocks (rate, concurrency, writer pause) are retried for
        up to ``max_wait_s``; the per-run request cap never is.
        """
        deadline = self._clock() + max_wait_s
        while True:
            with self.tracker.lock():
                pressure, healthy = self._writer_state()
                counters = self.tracker.snapshot(writer_pressure=pressure, writer_healthy=healthy)
                result = decide(request, self.policy, counters, kill_switch=self.kill_switch.is_enabled())
                if result.decision in ("forwarded", "dry_run"):
                    self.tracker.reserve(concurrent=result.decision == "forwarded")
                    return result
            transient = (
                result.reason == "budget_exceeded" and result.detail != "request_cap"
                and result.retry_after_s is not None and self._clock() + result.retry_after_s <= deadline
            )
            if not transient:
                return result
            self._sleep(result.retry_after_s)  # type: ignore[arg-type]

    def complete(self, verdict: Verdict) -> None:
        """Release the concurrency slot taken by a forwarded request."""
        if verdict.decision == "forwarded":
            self.tracker.release()
>>>>>>> Stashed changes
