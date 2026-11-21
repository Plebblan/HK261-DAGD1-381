"""Typed records accepted and returned by the evidence store."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Run:
    run_id: str
    mode: str | None = None
    started_at: str | None = None
    model_version: str | None = None
    allowlist_hash: str | None = None
    config_hash: str | None = None
    seed_id: str | None = None
    undocumented_policy: str | None = None
    isolation_mode: str | None = None
    target: str | None = None
    status: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Event:
    """A single redacted request/response record; callers assign event_id."""

    event_id: str
    run_id: str
    ts: str
    workflow_id: str | None = None
    sequence_id: str | None = None
    step_idx: int | None = None
    origin: str | None = None
    actor: str | None = None
    operation_id: str | None = None
    method: str | None = None
    host: str | None = None
    path: str | None = None
    query: str | None = None
    gateway_verdict: str | None = None
    gateway_reason: str | None = None
    rule_id: str | None = None
    status: int | None = None
    valid_request: bool | None = None
    request_redacted: Any = None
    response_redacted: Any = None
    raw_body_hash: str | None = None
    request_fingerprint: str | None = None
    response_hash: str | None = None
    normalized_hash: str | None = None
    normalization_version: str | None = None
    before_state_hash: str | None = None
    after_state_hash: str | None = None
    case_id: str | None = None
    tag: str | None = None
    undocumented: bool = False
    source_file: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    finding_id: str
    run_id: str
    family: str | None = None
    verdict: str | None = None
    evidence: Any = None
    reason_code: str | None = None
    review_state: str | None = None
    reviewer_note: str | None = None
    title: str | None = None
    summary: str = ""
    severity: str = "info"
    metadata: dict[str, Any] = field(default_factory=dict)
