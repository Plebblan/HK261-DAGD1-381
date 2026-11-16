CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    mode TEXT,
    started_at TEXT,
    model_version TEXT,
    allowlist_hash TEXT,
    config_hash TEXT,
    seed_id TEXT,
    undocumented_policy TEXT,
    isolation_mode TEXT,
    target TEXT,
    status TEXT,
    queue_stats TEXT,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS actor_sessions (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    actor TEXT NOT NULL,
    listener_port INTEGER,
    profile_path TEXT,
    PRIMARY KEY (run_id, actor)
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    workflow_id TEXT, sequence_id TEXT, step_idx INTEGER,
    ts TEXT NOT NULL, origin TEXT, actor TEXT, operation_id TEXT,
    method TEXT, host TEXT, path TEXT, query TEXT,
    gateway_verdict TEXT, gateway_reason TEXT, rule_id TEXT,
    status INTEGER, valid_request INTEGER,
    request_redacted TEXT, response_redacted TEXT,
    raw_body_hash TEXT, request_fingerprint TEXT, response_hash TEXT,
    normalized_hash TEXT, normalization_version TEXT,
    before_state_hash TEXT, after_state_hash TEXT,
    case_id TEXT, tag TEXT, undocumented INTEGER NOT NULL DEFAULT 0,
    source_file TEXT, metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ev_run ON events(run_id, step_idx);
CREATE INDEX IF NOT EXISTS ev_actor_op ON events(actor, operation_id);
CREATE INDEX IF NOT EXISTS ev_verdict ON events(gateway_verdict);

CREATE TABLE IF NOT EXISTS event_responses (
    event_id TEXT PRIMARY KEY REFERENCES events(event_id),
    ts TEXT NOT NULL,
    status INTEGER,
    response_redacted TEXT,
    response_hash TEXT,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS model_versions (
    version TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    reason TEXT,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    family TEXT, verdict TEXT, evidence TEXT, reason_code TEXT,
    review_state TEXT, reviewer_note TEXT,
    title TEXT, summary TEXT, severity TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
