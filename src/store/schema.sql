-- SQLite schema for the gateway event store.
-- This file is intentionally a scaffold for the first iteration.

PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'created',
    config_hash TEXT,
    allowlist_hash TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    actor TEXT,
    operation_id TEXT,
    verdict TEXT,
    event_type TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    payload TEXT
);

CREATE TABLE IF NOT EXISTS models (
    model_name TEXT NOT NULL,
    version TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (model_name, version)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT,
    severity TEXT,
    review_state TEXT DEFAULT 'new',
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
