"""SQLite adapter. All SQL and database connections live in this module."""

from __future__ import annotations

import json
import logging
import queue
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from src.common.logging import configure_component_logging, log_context

logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 2
_MAX_JSON_BYTES = 1_000_000
_EVENT_COLUMNS = (
    "event_id run_id workflow_id sequence_id step_idx ts origin actor operation_id "
    "method host path query gateway_verdict gateway_reason rule_id status valid_request "
    "request_redacted response_redacted raw_body_hash request_fingerprint response_hash "
    "normalized_hash normalization_version before_state_hash after_state_hash case_id tag "
    "undocumented source_file metadata"
).split()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _json(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)
    raw = encoded.encode("utf-8")
    if len(raw) > _MAX_JSON_BYTES:
        encoded = json.dumps({"_truncated": True, "original_bytes": len(raw), "preview": raw[:_MAX_JSON_BYTES // 2].decode("utf-8", "ignore")}, ensure_ascii=False, separators=(",", ":"))
    return encoded


class Store:
    """Narrow SQLite API with one serialized writer and independent readers."""

    def __init__(
        self,
        path: str | Path,
        *,
        logging_config: Mapping[str, Any] | None = None,
        log_dir: str | Path | None = None,
    ):
        self.path = str(path)
        self._uri = self.path == ":memory:"
        self._logging_config = logging_config
        self._log_dir = Path(log_dir) if log_dir is not None else self._infer_log_dir(path)
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

    @staticmethod
    def _infer_log_dir(path: str | Path) -> Path | None:
        database_path = Path(path)
        if database_path.name == "store.db" and database_path.parent.parent.name == "runs":
            return database_path.parent / "logs"
        return None

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5.0, check_same_thread=False, uri=self._uri)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _writer_main(self) -> None:
        try:
            conn = self._connect()
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
            conn.executescript(schema)
            run_columns = {row["name"] for row in conn.execute("PRAGMA table_info(runs)")}
            if "queue_stats" not in run_columns:
                conn.execute("ALTER TABLE runs ADD COLUMN queue_stats TEXT")
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
        if self._log_dir is not None:
            configure_component_logging(
                self._log_dir,
                component="store",
                run_id=run_id,
                config=self._logging_config,
                reset=True,
                logger_name=logger.name,
            )
        allowed = {"mode", "started_at", "model_version", "allowlist_hash", "config_hash", "seed_id", "undocumented_policy", "isolation_mode", "status", "metadata"}
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

    def append_event(self, *, event_id: str, run_id: str, ts: str | None = None, **kwargs: Any) -> None:
        event = {key: kwargs.pop(key, None) for key in _EVENT_COLUMNS if key not in {"event_id", "run_id", "ts"}}
        event.update(event_id=event_id, run_id=run_id, ts=ts or kwargs.pop("ts", None) or _utc_now())
        extra = {**(event.get("metadata") or {}), **kwargs}
        event["metadata"] = extra
        event["undocumented"] = int(bool(event["undocumented"]))
        event["valid_request"] = None if event["valid_request"] is None else int(bool(event["valid_request"]))
        for key in ("request_redacted", "response_redacted"):
            event[key] = _json(event[key]) if event[key] is not None else None
        event["metadata"] = _json(event["metadata"])
        sql = f"INSERT INTO events ({', '.join(_EVENT_COLUMNS)}) VALUES ({', '.join('?' for _ in _EVENT_COLUMNS)})"
        self._write(
            lambda conn: conn.execute(sql, [event[key] for key in _EVENT_COLUMNS]),
            run_id=run_id,
            event_id=event_id,
            operation_id=event["operation_id"],
        )

    def append_events(self, events: list[dict[str, Any]]) -> None:
        prepared = []
        for item in events:
            event = dict(item)
            event_id, run_id = event.pop("event_id"), event.pop("run_id")
            ts = event.pop("ts", None)
            prepared.append((event_id, run_id, ts, event))
        def write(conn: sqlite3.Connection) -> None:
            for event_id, run_id, ts, event in prepared:
                self._insert_event(conn, event_id, run_id, ts, event)
        context: dict[str, str | None] = {}
        if prepared:
            run_ids = {item[1] for item in prepared}
            if len(run_ids) == 1:
                context["run_id"] = prepared[0][1]
            if len(prepared) == 1:
                context["event_id"] = prepared[0][0]
                context["operation_id"] = prepared[0][3].get("operation_id")
        self._write(write, **context)

    def append_responses(self, responses: list[dict[str, Any]]) -> None:
        """Atomically commit response-side records for previously stored events."""
        prepared = []
        for response in responses:
            row = dict(response)
            event_id = row.pop("event_id")
            ts = row.pop("ts", None) or _utc_now()
            raw_body = row.pop("response_redacted", None)
            response_body = _json(raw_body) if raw_body is not None else None
            metadata = _json(row.pop("metadata", {}))
            prepared.append((event_id, ts, row.pop("status", None), response_body, row.pop("response_hash", None), metadata))

        def write(conn: sqlite3.Connection) -> None:
            for values in prepared:
                conn.execute(
                    "INSERT INTO event_responses(event_id, ts, status, response_redacted, response_hash, metadata) VALUES (?, ?, ?, ?, ?, ?)",
                    values,
                )

        context: dict[str, str | None] = {}
        if len(prepared) == 1:
            context["event_id"] = prepared[0][0]
        self._write(write, **context)

    def update_queue_stats(self, *, run_id: str, stats: Mapping[str, Any]) -> None:
        """Persist final writer counters once the run has stopped accepting writes."""
        self._write(
            lambda conn: conn.execute("UPDATE runs SET queue_stats = ? WHERE run_id = ?", (_json(stats), run_id)),
            run_id=run_id,
        )

    def mark_run_degraded(self, *, run_id: str) -> None:
        """Record that audit availability forced the run to fail closed."""
        self._write(
            lambda conn: conn.execute("UPDATE runs SET status = 'degraded' WHERE run_id = ?", (run_id,)),
            run_id=run_id,
        )

    @staticmethod
    def _insert_event(conn: sqlite3.Connection, event_id: str, run_id: str, ts: str | None, values: dict[str, Any]) -> None:
        event = {key: values.get(key) for key in _EVENT_COLUMNS if key not in {"event_id", "run_id", "ts"}}
        event.update(event_id=event_id, run_id=run_id, ts=ts or _utc_now())
        event["undocumented"] = int(bool(event["undocumented"]))
        event["valid_request"] = None if event["valid_request"] is None else int(bool(event["valid_request"]))
        for key in ("request_redacted", "response_redacted"):
            event[key] = _json(event[key]) if event[key] is not None else None
        event["metadata"] = _json(event["metadata"] if event["metadata"] is not None else {})
        conn.execute(f"INSERT INTO events ({', '.join(_EVENT_COLUMNS)}) VALUES ({', '.join('?' for _ in _EVENT_COLUMNS)})", [event[key] for key in _EVENT_COLUMNS])

    def get_events(self, *, run_id: str, actor: str | None = None, operation_id: str | None = None, verdict: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        clauses, params = ["run_id = ?"], [run_id]
        for column, value in (("actor", actor), ("operation_id", operation_id), ("gateway_verdict", verdict)):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        sql = f"SELECT events.*, event_responses.ts AS response_ts, event_responses.status AS response_status, event_responses.response_redacted AS committed_response, event_responses.response_hash AS committed_response_hash, event_responses.metadata AS response_metadata FROM events LEFT JOIN event_responses USING(event_id) WHERE {' AND '.join('events.' + clause.replace(' = ?', ' = ?') for clause in clauses)} ORDER BY events.rowid"
        if limit is not None:
            if limit < 0:
                raise ValueError("limit must be non-negative")
            sql += " LIMIT ?"
            params.append(limit)
        with self._connect() as conn:
            results = []
            for row in conn.execute(sql, params):
                item = self._record(row, ("request_redacted", "response_redacted", "metadata", "committed_response", "response_metadata"))
                if item.get("response_ts") is not None:
                    item["response_redacted"] = item.pop("committed_response")
                    item["status"] = item.pop("response_status")
                    item["response_hash"] = item.pop("committed_response_hash")
                    item["response_metadata"] = item.pop("response_metadata")
                    item["incomplete"] = False
                else:
                    item["incomplete"] = item.get("response_redacted") is None
                    item.pop("committed_response", None)
                    item.pop("committed_response_hash", None)
                    item.pop("response_metadata", None)
                    item.pop("response_status", None)
                results.append(item)
            return results

    def count_incomplete_events(self, *, run_id: str) -> int:
        with self._connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM events LEFT JOIN event_responses USING(event_id) WHERE events.run_id = ? AND event_responses.event_id IS NULL AND events.response_redacted IS NULL",
                (run_id,),
            ).fetchone()[0]

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
        with self._connect() as conn:
            row = conn.execute("SELECT payload FROM model_versions WHERE version = ?", (key,)).fetchone()
        return json.loads(row["payload"]) if row else None

    def upsert_finding(self, *, finding_id: str, run_id: str, **kwargs: Any) -> None:
        columns = ("family", "verdict", "evidence", "reason_code", "review_state", "reviewer_note", "title", "summary", "severity", "metadata")
        values = {key: kwargs.get(key) for key in columns}
        for key in ("evidence", "metadata"):
            values[key] = _json(values[key] if values[key] is not None else ({} if key == "metadata" else None))
        values.update(finding_id=finding_id, run_id=run_id, created_at=_utc_now())
        names = ["finding_id", "run_id", *columns, "created_at"]
        updates = ", ".join(f"{key}=excluded.{key}" for key in columns)
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
        with self._connect() as conn:
            return [self._record(row, ("evidence", "metadata")) for row in conn.execute(sql, params)]

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._queue.put(None)
            self._writer.join()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
