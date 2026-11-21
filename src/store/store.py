"""SQLite adapter. All SQL and database connections live in this module."""

from __future__ import annotations

import json
import logging
import queue
import sqlite3
import threading
import uuid
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import quote

from src.common.logging import log_context
from src.common.redaction import redact_payload

logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 3
_MAX_JSON_BYTES = 1_000_000
_EVENT_COLUMNS = (
    "event_id run_id workflow_id sequence_id step_idx ts origin actor operation_id "
    "method host path query gateway_verdict gateway_reason rule_id status valid_request "
    "request_redacted response_redacted raw_body_hash request_fingerprint response_hash "
    "normalized_hash normalization_version before_state_hash after_state_hash case_id tag "
    "undocumented source_file metadata"
).split()
_RESPONSE_FIELDS = {
    "event_id", "ts", "status", "elapsed_ms", "response_redacted", "response_hash",
    "normalized_hash", "normalization_version", "before_state_hash", "after_state_hash", "metadata",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _json(value: Any, *, truncate: bool = False) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)
    raw = encoded.encode("utf-8")
    if len(raw) > _MAX_JSON_BYTES:
        if not truncate:
            raise ValueError(f"serialized value exceeds {_MAX_JSON_BYTES} bytes")
        encoded = json.dumps({"_truncated": True, "original_bytes": len(raw), "preview": raw[:_MAX_JSON_BYTES // 2].decode("utf-8", "ignore")}, ensure_ascii=False, separators=(",", ":"))
    return encoded


class Store:
    """Narrow SQLite API with one serialized writer and independent readers."""

    def __init__(
        self,
        path: str | Path,
        *,
        synchronous: str = "NORMAL",
        read_pool_size: int = 4,
    ):
        if synchronous.upper() not in {"OFF", "NORMAL", "FULL", "EXTRA"}:
            raise ValueError("synchronous must be OFF, NORMAL, FULL, or EXTRA")
        if read_pool_size < 1:
            raise ValueError("read_pool_size must be positive")
        self.path = str(path)
        self._uri = self.path == ":memory:"
        self._synchronous = synchronous.upper()
        self._readers: queue.LifoQueue[sqlite3.Connection] = queue.LifoQueue(read_pool_size)
        self._reader_count = 0
        self._reader_lock = threading.Condition()
        self._reader_leases = 0
        self._read_pool_size = read_pool_size
        if self._uri:
            self.path = f"file:store-{uuid.uuid4().hex}?mode=memory&cache=shared"
        else:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._queue: queue.Queue[Any] = queue.Queue()
        self._closed = False
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None
        self._writer = threading.Thread(target=self._writer_main, name="store-writer", daemon=True)
        self._writer.start()
        self._ready.wait()
        if self._startup_error is not None:
            self._writer.join()
            raise RuntimeError("store structure initialization failed") from self._startup_error

    def _connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        database = self.path
        uri = self._uri
        if read_only and not self._uri:
            database = f"file:{quote(str(Path(self.path).resolve()))}?mode=ro"
            uri = True
        conn = sqlite3.connect(database, timeout=5.0, check_same_thread=False, uri=uri)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        if read_only:
            conn.execute("PRAGMA query_only=ON")
        return conn

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        with self._reader_lock:
            while True:
                if self._closed:
                    raise RuntimeError("Store is closed")
                try:
                    conn = self._readers.get_nowait()
                    break
                except queue.Empty:
                    if self._reader_count < self._read_pool_size:
                        self._reader_count += 1
                        try:
                            conn = self._connect(read_only=True)
                        except BaseException:
                            self._reader_count -= 1
                            self._reader_lock.notify()
                            raise
                        break
                    self._reader_lock.wait()
            self._reader_leases += 1
        try:
            yield conn
        finally:
            with self._reader_lock:
                self._reader_leases -= 1
                if self._closed:
                    conn.close()
                    self._reader_count -= 1
                else:
                    self._readers.put(conn)
                self._reader_lock.notify_all()

    def _writer_main(self) -> None:
        try:
            conn = self._connect()
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(f"PRAGMA synchronous={self._synchronous}")
            schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
            conn.executescript(schema)
            run_columns = {row["name"] for row in conn.execute("PRAGMA table_info(runs)")}
            if "queue_stats" not in run_columns:
                conn.execute("ALTER TABLE runs ADD COLUMN queue_stats TEXT")
            response_columns = {row["name"] for row in conn.execute("PRAGMA table_info(event_responses)")}
            for column, sql_type in (
                ("elapsed_ms", "REAL"),
                ("normalized_hash", "TEXT"),
                ("normalization_version", "TEXT"),
                ("before_state_hash", "TEXT"),
                ("after_state_hash", "TEXT"),
            ):
                if column not in response_columns:
                    conn.execute(f"ALTER TABLE event_responses ADD COLUMN {column} {sql_type}")
            latest_version = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
            if latest_version is None or latest_version < _SCHEMA_VERSION:
                conn.execute("INSERT INTO schema_version(version, applied_at) VALUES (?, ?)", (_SCHEMA_VERSION, _utc_now()))
                conn.commit()
        except SystemExit as exc:
            logger.exception("store structure_failure: system exit during initialization (exit_code=%r)", exc.code)
            self._startup_error = exc
            self._ready.set()
            return
        except SyntaxError:
            logger.exception("store structure_failure: Python syntax error while loading store structure")
            self._startup_error = SyntaxError("store structure contains invalid Python syntax")
            self._ready.set()
            return
        except sqlite3.Error:
            logger.exception("store structure_failure: schema SQL or database structure is invalid")
            self._startup_error = RuntimeError("store schema SQL or database structure is invalid")
            self._ready.set()
            return
        except Exception as exc:
            logger.exception("store structure_failure: schema or database initialization failed")
            self._startup_error = exc
            self._ready.set()
            return
        self._ready.set()
        while True:
            item = self._queue.get()
            if item is None:
                break
            fn, done, result, context = item
            with log_context(**context):
                try:
                    result.append(fn(conn))
                    conn.commit()
                except SystemExit as exc:
                    conn.rollback()
                    logger.exception("store action_failure: system exit during database action")
                    result.append(exc)
                except BaseException as exc:
                    conn.rollback()
                    if isinstance(exc, sqlite3.IntegrityError):
                        logger.exception("store action_failure: insert constraint failure")
                    else:
                        logger.exception("store action_failure: database action failed")
                    result.append(exc)
                finally:
                    done.set()
        conn.close()

    def _write(
        self,
        fn: Callable[[sqlite3.Connection], Any],
        *,
        run_id: str | None = None,
        event_id: str | None = None,
        operation_id: str | None = None,
    ) -> Any:
        if self._closed:
            raise RuntimeError("Store is closed")
        done = threading.Event()
        result: list[Any] = []
        context = {
            "run_id": run_id,
            "event_id": event_id,
            "operation_id": operation_id,
        }
        self._queue.put((fn, done, result, context))
        done.wait()
        if not result:
            raise RuntimeError("Store writer stopped before completing the action")
        value = result[0]
        if isinstance(value, BaseException):
            raise value
        return value

    @staticmethod
    def _record(row: sqlite3.Row, json_fields: tuple[str, ...] = ()) -> dict[str, Any]:
        result = dict(row)
        for key in json_fields:
            if result.get(key) is not None:
                result[key] = json.loads(result[key])
        return result

    def create_run(self, *, run_id: str, target: str | None = None, **kwargs: Any) -> None:
        allowed = {"mode", "started_at", "model_version", "allowlist_hash", "config_hash", "seed_id", "undocumented_policy", "isolation_mode", "status", "metadata"}
        unknown = set(kwargs) - allowed
        if unknown:
            raise TypeError(f"unknown run fields: {', '.join(sorted(unknown))}")
        fields = {key: value for key, value in kwargs.items() if key in allowed}
        fields["run_id"] = run_id
        fields["target"] = target
        fields.setdefault("started_at", _utc_now())
        fields.setdefault("metadata", {})
        fields["metadata"] = _json(fields["metadata"])
        columns = list(fields)
        sql = f"INSERT INTO runs ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})"
        self._write(
            lambda conn: conn.execute(sql, [fields[key] for key in columns]),
            run_id=run_id,
        )

    def record_actor_session(self, *, run_id: str, actor: str, listener_port: int | None = None, profile_path: str | None = None) -> None:
        self._write(
            lambda conn: conn.execute("INSERT INTO actor_sessions(run_id, actor, listener_port, profile_path) VALUES (?, ?, ?, ?) ON CONFLICT(run_id, actor) DO UPDATE SET listener_port=excluded.listener_port, profile_path=excluded.profile_path", (run_id, actor, listener_port, profile_path)),
            run_id=run_id,
        )

    @staticmethod
    def _prepare_event(item: Mapping[str, Any]) -> dict[str, Any]:
        unknown = set(item) - set(_EVENT_COLUMNS)
        if unknown:
            raise TypeError(f"unknown event fields: {', '.join(sorted(unknown))}")
        if not item.get("event_id") or not item.get("run_id"):
            raise ValueError("event_id and run_id are required")
        event = {column: item.get(column) for column in _EVENT_COLUMNS}
        event["ts"] = event["ts"] or _utc_now()
        event["undocumented"] = int(bool(event["undocumented"]))
        event["valid_request"] = None if event["valid_request"] is None else int(bool(event["valid_request"]))
        for key in ("request_redacted", "response_redacted"):
            if event[key] is not None:
                event[key] = _json(redact_payload(event[key]), truncate=True)
        event["metadata"] = _json(redact_payload(event["metadata"] or {}))
        return event

    def append_event(self, *, event_id: str, run_id: str, **kwargs: Any) -> None:
        self.append_events([{"event_id": event_id, "run_id": run_id, **kwargs}])

    def append_events(self, events: list[Mapping[str, Any]]) -> int:
        prepared = [self._prepare_event(item) for item in events]

        def write(conn: sqlite3.Connection) -> int:
            inserted = 0
            for event in prepared:
                cursor = conn.execute(
                    f"INSERT INTO events ({', '.join(_EVENT_COLUMNS)}) VALUES ({', '.join('?' for _ in _EVENT_COLUMNS)}) ON CONFLICT(event_id) DO NOTHING",
                    [event[key] for key in _EVENT_COLUMNS],
                )
                inserted += cursor.rowcount
            return inserted

        context: dict[str, str | None] = {}
        if prepared:
            run_ids = {item["run_id"] for item in prepared}
            if len(run_ids) == 1:
                context["run_id"] = prepared[0]["run_id"]
            if len(prepared) == 1:
                context["event_id"] = prepared[0]["event_id"]
                context["operation_id"] = prepared[0]["operation_id"]
        return self._write(write, **context)

    def append_responses(self, responses: list[dict[str, Any]]) -> int:
        """Atomically commit response-side records for previously stored events."""
        prepared = []
        for response in responses:
            unknown = set(response) - _RESPONSE_FIELDS
            if unknown:
                raise TypeError(f"unknown response fields: {', '.join(sorted(unknown))}")
            if not response.get("event_id"):
                raise ValueError("event_id is required for a response")
            row = dict(response)
            body = row.get("response_redacted")
            metadata = redact_payload(row.get("metadata") or {})
            prepared.append({
                "event_id": row["event_id"],
                "ts": row.get("ts") or _utc_now(),
                "status": row.get("status"),
                "elapsed_ms": row.get("elapsed_ms"),
                "response_redacted": _json(redact_payload(body), truncate=True) if body is not None else None,
                "response_hash": row.get("response_hash"),
                "normalized_hash": row.get("normalized_hash"),
                "normalization_version": row.get("normalization_version"),
                "before_state_hash": row.get("before_state_hash"),
                "after_state_hash": row.get("after_state_hash"),
                "metadata": _json(metadata),
            })

        def write(conn: sqlite3.Connection) -> int:
            inserted = 0
            for row in prepared:
                cursor = conn.execute(
                    "INSERT INTO event_responses(event_id, ts, status, elapsed_ms, response_redacted, response_hash, normalized_hash, normalization_version, before_state_hash, after_state_hash, metadata) VALUES (:event_id, :ts, :status, :elapsed_ms, :response_redacted, :response_hash, :normalized_hash, :normalization_version, :before_state_hash, :after_state_hash, :metadata) ON CONFLICT(event_id) DO NOTHING",
                    row,
                )
                inserted += cursor.rowcount
            return inserted

        context: dict[str, str | None] = {}
        if len(prepared) == 1:
            context["event_id"] = prepared[0]["event_id"]
        return self._write(write, **context)

    def update_queue_stats(self, *, run_id: str, stats: Mapping[str, Any]) -> None:
        """Persist final writer counters once the run has stopped accepting writes."""
        self._write(
            lambda conn: conn.execute("UPDATE runs SET queue_stats = ? WHERE run_id = ?", (_json(stats), run_id)),
            run_id=run_id,
        )

    def finish_run(self, *, run_id: str, status: str, stats: Mapping[str, Any] | None = None) -> None:
        """Persist final run status and audit-writer counters."""
        if status not in {"completed", "failed", "degraded", "cancelled"}:
            raise ValueError("invalid terminal run status")
        self._write(
            lambda conn: conn.execute(
                "UPDATE runs SET status = ?, queue_stats = ? WHERE run_id = ?",
                (status, _json(stats or {}), run_id),
            ),
            run_id=run_id,
        )

    def mark_run_degraded(self, *, run_id: str) -> None:
        """Record that audit availability forced the run to fail closed."""
        self._write(
            lambda conn: conn.execute("UPDATE runs SET status = 'degraded' WHERE run_id = ?", (run_id,)),
            run_id=run_id,
        )

    def get_events(self, *, run_id: str, actor: str | None = None, operation_id: str | None = None, verdict: str | None = None, limit: int | None = None) -> Iterator[dict[str, Any]]:
        """Yield a run's events in insertion order using a pooled read-only connection."""
        clauses, params = ["run_id = ?"], [run_id]
        for column, value in (("actor", actor), ("operation_id", operation_id), ("gateway_verdict", verdict)):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        sql = f"SELECT events.*, event_responses.ts AS response_ts, event_responses.status AS response_status, event_responses.elapsed_ms AS response_elapsed_ms, event_responses.response_redacted AS committed_response, event_responses.response_hash AS committed_response_hash, event_responses.normalized_hash AS response_normalized_hash, event_responses.normalization_version AS response_normalization_version, event_responses.before_state_hash AS response_before_state_hash, event_responses.after_state_hash AS response_after_state_hash, event_responses.metadata AS response_metadata FROM events LEFT JOIN event_responses USING(event_id) WHERE {' AND '.join('events.' + clause for clause in clauses)} ORDER BY events.rowid"
        if limit is not None:
            if limit < 0:
                raise ValueError("limit must be non-negative")
            sql += " LIMIT ?"
            params.append(limit)
        with self._read_connection() as conn:
            with closing(conn.execute(sql, params)) as cursor:
                for row in cursor:
                    item = self._record(row, ("request_redacted", "response_redacted", "metadata", "committed_response", "response_metadata"))
                    if item.get("response_ts") is not None:
                        item["response_redacted"] = item.pop("committed_response")
                        item["status"] = item.pop("response_status")
                        item["elapsed_ms"] = item.pop("response_elapsed_ms")
                        item["response_hash"] = item.pop("committed_response_hash")
                        for key in ("normalized_hash", "normalization_version", "before_state_hash", "after_state_hash"):
                            response_key = f"response_{key}"
                            if item.get(response_key) is not None:
                                item[key] = item[response_key]
                            item.pop(response_key, None)
                        item["response_metadata"] = item.pop("response_metadata")
                        item["incomplete"] = False
                    else:
                        item["incomplete"] = (
                            item.get("gateway_verdict") == "forwarded"
                            and item.get("response_redacted") is None
                        )
                        for key in ("committed_response", "response_status", "response_elapsed_ms", "committed_response_hash", "response_normalized_hash", "response_normalization_version", "response_before_state_hash", "response_after_state_hash", "response_metadata"):
                            item.pop(key, None)
                    yield item

    def count_incomplete_events(self, *, run_id: str) -> int:
        with self._read_connection() as conn:
            with closing(conn.execute(
                "SELECT COUNT(*) FROM events LEFT JOIN event_responses USING(event_id) WHERE events.run_id = ? AND events.gateway_verdict = 'forwarded' AND event_responses.event_id IS NULL AND events.response_redacted IS NULL",
                (run_id,),
            )) as cursor:
                return cursor.fetchone()[0]

    def put_model(self, *, version: str, payload: Any, reason: str | None = None, model_name: str | None = None) -> None:
        if model_name:
            version = f"{model_name}:{version}"
        def write(conn: sqlite3.Connection) -> None:
            try:
                conn.execute("INSERT INTO model_versions(version, created_at, reason, payload) VALUES (?, ?, ?, ?)", (version, _utc_now(), reason, _json(payload)))
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"model version already exists: {version}") from exc
        self._write(write)

    def get_model(self, *, version: str | None = None, model_name: str | None = None) -> Any:
        if version is None:
            raise ValueError("version is required")
        key = f"{model_name}:{version}" if model_name else version
        with self._read_connection() as conn:
            with closing(conn.execute("SELECT payload FROM model_versions WHERE version = ?", (key,))) as cursor:
                row = cursor.fetchone()
        return json.loads(row["payload"]) if row else None

    def upsert_finding(self, *, finding_id: str, run_id: str, **kwargs: Any) -> None:
        columns = ("family", "verdict", "evidence", "reason_code", "review_state", "reviewer_note", "title", "summary", "severity", "metadata")
        unknown = set(kwargs) - set(columns)
        if unknown:
            raise TypeError(f"unknown finding fields: {', '.join(sorted(unknown))}")
        values = {key: kwargs.get(key) for key in columns}
        for key in ("evidence", "metadata"):
            value = values[key]
            if key == "metadata" and value is None:
                value = {}
            values[key] = _json(redact_payload(value)) if value is not None else None
        values.update(finding_id=finding_id, run_id=run_id, created_at=_utc_now())
        names = ["finding_id", "run_id", *columns, "created_at"]
        updates = ", ".join(
            f"{key}=COALESCE(excluded.{key}, findings.{key})"
            for key in columns
            if key in kwargs and kwargs[key] is not None
        )
        if not updates:
            updates = "finding_id=excluded.finding_id"
        sql = f"INSERT INTO findings ({', '.join(names)}) VALUES ({', '.join('?' for _ in names)}) ON CONFLICT(finding_id) DO UPDATE SET {updates}"
        self._write(
            lambda conn: conn.execute(sql, [values[key] for key in names]),
            run_id=run_id,
        )

    def list_findings(self, *, run_id: str, review_state: str | None = None) -> list[dict[str, Any]]:
        sql, params = "SELECT * FROM findings WHERE run_id = ?", [run_id]
        if review_state is not None:
            sql += " AND review_state = ?"
            params.append(review_state)
        sql += " ORDER BY created_at, rowid"
        with self._read_connection() as conn:
            with closing(conn.execute(sql, params)) as cursor:
                return [self._record(row, ("evidence", "metadata")) for row in cursor]

    def close(self) -> None:
        if not self._closed:
            with self._reader_lock:
                self._closed = True
                self._reader_lock.notify_all()
            self._queue.put(None)
            self._writer.join()
            with self._reader_lock:
                while self._reader_leases:
                    self._reader_lock.wait()
            while True:
                try:
                    self._readers.get_nowait().close()
                    with self._reader_lock:
                        self._reader_count -= 1
                except queue.Empty:
                    break

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
