"""Durable, bounded, group-commit write path for proxy and gateway callers."""

from __future__ import annotations

import asyncio
import json
import logging
import queue
import threading
import time
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any, Callable, Mapping

from .store import Store

logger = logging.getLogger(__name__)


class AuditUnavailable(RuntimeError):
    """The audit record could not be durably committed within its deadline."""


@dataclass(frozen=True)
class WriterHealth:
    depth: int
    uncommitted_bytes: int
    pressure: float
    state: str
    last_error: str | None
    pressure_state: str


@dataclass
class _Write:
    kind: str
    payload: Any
    loop: asyncio.AbstractEventLoop | None
    future: asyncio.Future[Any] | None
    size: int
    queued_at: float


class StoreWriter:
    """Async admission facade with bounded backpressure and durable acknowledgments."""

    def __init__(
        self,
        store: Store,
        *,
        batch_max_events: int = 50,
        batch_max_ms: int = 5,
        queue_max_events: int = 10_000,
        queue_max_bytes: int = 67_108_864,
        throttle_threshold: float = 0.5,
        pause_threshold: float = 0.9,
        audit_timeout_ms: int = 2_000,
        run_id: str | None = None,
    ):
        if min(batch_max_events, queue_max_events, queue_max_bytes, audit_timeout_ms) <= 0 or batch_max_ms < 0:
            raise ValueError("writer limits must be positive (batch_max_ms may be zero)")
        if not 0 <= throttle_threshold < pause_threshold <= 1:
            raise ValueError("thresholds must satisfy 0 <= throttle < pause <= 1")
        self.store = store
        self.batch_max_events = batch_max_events
        self.batch_max_ms = batch_max_ms / 1000
        self.queue_max_events = queue_max_events
        self.queue_max_bytes = queue_max_bytes
        self.throttle_threshold = throttle_threshold
        self.pause_threshold = pause_threshold
        self.audit_timeout = audit_timeout_ms / 1000
        self.run_id = run_id
        self._queue: queue.Queue[_Write | None] = queue.Queue()
        self._condition = threading.Condition()
        self._outstanding_events = 0
        self._outstanding_bytes = 0
        self._high_events = 0
        self._high_bytes = 0
        self._throttled_seconds = 0.0
        self._paused_seconds = 0.0
        self._last_pressure_change = time.monotonic()
        self._last_pressure_state = "normal"
        self._write_failures = 0
        self._incomplete_events = 0
        self._dropped = 0
        self._last_error: str | None = None
        self._degraded_persisted = False
        self._state = "healthy"
        self._closing = False
        self._thread = threading.Thread(target=self._run, name="store-writer-batcher", daemon=True)
        self._thread.start()

    @staticmethod
    def _size(payload: Any) -> int:
        try:
            return len(json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8"))
        except Exception:
            return 1

    @staticmethod
    def _record(value: Any) -> dict[str, Any]:
        if isinstance(value, Mapping):
            return dict(value)
        if is_dataclass(value) and not isinstance(value, type):
            return asdict(value)
        raise TypeError("writer records must be mappings or dataclass instances")

    def _pressure_locked(self) -> float:
        event_pressure = self._outstanding_events / self.queue_max_events
        byte_pressure = self._outstanding_bytes / self.queue_max_bytes
        return min(1.0, max(event_pressure, byte_pressure))

    def _set_pressure_state_locked(self, pressure: float, now: float) -> None:
        state = "paused" if pressure >= self.pause_threshold else "throttled" if pressure >= self.throttle_threshold else "normal"
        elapsed = max(0.0, now - self._last_pressure_change)
        if self._last_pressure_state == "throttled":
            self._throttled_seconds += elapsed
        elif self._last_pressure_state == "paused":
            self._paused_seconds += elapsed
        self._last_pressure_state = state
        self._last_pressure_change = now

    def health(self) -> WriterHealth:
        with self._condition:
            pressure = self._pressure_locked()
            now = time.monotonic()
            self._set_pressure_state_locked(pressure, now)
            pressure_state = self._last_pressure_state
            state = self._state
            if state == "healthy" and pressure_state == "paused":
                state = "paused"
            elif state == "healthy" and pressure_state == "throttled":
                state = "throttled"
            return WriterHealth(self._outstanding_events, self._outstanding_bytes, pressure, state, self._last_error, pressure_state)

    def _admit(self, item: _Write, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        with self._condition:
            if self._closing or self._state != "healthy":
                raise AuditUnavailable(self._last_error or f"writer is {self._state}")
            while (
                self._outstanding_events >= self.queue_max_events
                or self._outstanding_bytes + item.size > self.queue_max_bytes
            ):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._write_failures += 1
                    raise AuditUnavailable("writer queue remained full until audit timeout")
                self._condition.wait(remaining)
                if self._closing or self._state != "healthy":
                    raise AuditUnavailable(self._last_error or f"writer is {self._state}")
            self._outstanding_events += 1
            self._outstanding_bytes += item.size
            self._high_events = max(self._high_events, self._outstanding_events)
            self._high_bytes = max(self._high_bytes, self._outstanding_bytes)
            self._set_pressure_state_locked(self._pressure_locked(), time.monotonic())
            self._queue.put(item)

    async def _submit(self, kind: str, payload: Any, *, size_payload: Any = None) -> Any:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.audit_timeout
        future: asyncio.Future[Any] = loop.create_future()
        item = _Write(kind, payload, loop, future, self._size(payload if size_payload is None else size_payload), time.monotonic())
        try:
            await asyncio.to_thread(self._admit, item, self.audit_timeout)
            remaining = deadline - loop.time()
            if remaining <= 0:
                self._mark_unhealthy("audit commit exceeded audit_timeout_ms")
                raise AuditUnavailable("audit commit exceeded audit_timeout_ms")
            return await asyncio.wait_for(asyncio.shield(future), timeout=remaining)
        except asyncio.TimeoutError as exc:
            self._mark_unhealthy("audit commit exceeded audit_timeout_ms")
            raise AuditUnavailable("audit commit exceeded audit_timeout_ms") from exc
        except AuditUnavailable:
            self._mark_unhealthy("writer admission failed before durable commit")
            raise

    async def write_event(self, event: Mapping[str, Any]) -> None:
        """Commit the request-side event before the caller forwards its request."""
        await self._submit("event", self._record(event))

    async def write_response(self, response: Mapping[str, Any]) -> None:
        """Commit the response side before the caller releases the response."""
        await self._submit("response", self._record(response))

    async def write_control(self, cmd: Any) -> Any:
        """Commit a control operation (method name plus kwargs, or a callable)."""
        return await self._submit("control", cmd)

    def _mark_unhealthy(self, error: str) -> None:
        persist_degraded = False
        with self._condition:
            self._state = "degraded"
            self._last_error = error
            if self.run_id is not None and not self._degraded_persisted:
                self._degraded_persisted = True
                persist_degraded = True
            self._condition.notify_all()
        logger.error("store writer degraded: %s", error, extra={"run_id": self.run_id})
        if persist_degraded:
            threading.Thread(
                target=self._persist_degraded,
                name="store-writer-degraded-marker",
                daemon=True,
            ).start()

    def _persist_degraded(self) -> None:
        try:
            self.store.mark_run_degraded(run_id=self.run_id)  # type: ignore[arg-type]
        except Exception:
            logger.exception("store writer could not persist degraded run state", extra={"run_id": self.run_id})

    def _resolve(self, item: _Write, *, result: Any = None, error: BaseException | None = None) -> None:
        if item.loop is None or item.future is None:
            return
        def finish() -> None:
            if item.future is None or item.future.done():
                return
            if error is None:
                item.future.set_result(result)
            else:
                item.future.set_exception(error)
        item.loop.call_soon_threadsafe(finish)

    def _execute_control(self, command: Any) -> Any:
        if callable(command):
            return command(self.store)
        if isinstance(command, Mapping):
            method = command.get("method")
            kwargs = command.get("kwargs", {})
        elif isinstance(command, tuple) and len(command) == 2:
            method, kwargs = command
        else:
            raise ValueError("control command must be callable, (method, kwargs), or a mapping")
        if method not in {"create_run", "put_model", "upsert_finding", "record_actor_session"}:
            raise ValueError(f"unsupported store control command: {method!r}")
        return getattr(self.store, method)(**dict(kwargs))

    def _finish_batch(self, batch: list[_Write]) -> None:
        if not batch:
            return
        kind = batch[0].kind
        try:
            if kind == "event":
                result = self.store.append_events([item.payload for item in batch])
            elif kind == "response":
                result = self.store.append_responses([item.payload for item in batch])
            else:
                result = self._execute_control(batch[0].payload)
            for item in batch:
                self._resolve(item, result=result)
        except BaseException as exc:
            self._mark_unhealthy(str(exc))
            with self._condition:
                self._write_failures += len(batch)
                if kind == "event":
                    self._incomplete_events += len(batch)
            for item in batch:
                self._resolve(item, error=exc)
        finally:
            size = sum(item.size for item in batch)
            with self._condition:
                self._outstanding_events -= len(batch)
                self._outstanding_bytes -= size
                self._set_pressure_state_locked(self._pressure_locked(), time.monotonic())
                self._condition.notify_all()

    def _run(self) -> None:
        while True:
            first = self._queue.get()
            if first is None:
                return
            batch = [first]
            deadline = time.monotonic() + self.batch_max_ms
            while first.kind != "control" and len(batch) < self.batch_max_events:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    item = self._queue.get(timeout=remaining)
                except queue.Empty:
                    break
                if item is None:
                    self._queue.put(None)
                    break
                if item.kind != first.kind:
                    self._queue.put(item)
                    break
                batch.append(item)
            self._finish_batch(batch)

    def flush(self, timeout: float | None = None) -> None:
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while self._outstanding_events:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError("timed out flushing store writer")
                self._condition.wait(remaining)
            if self._state == "degraded":
                raise AuditUnavailable(self._last_error or "writer is degraded")

    def stats(self) -> dict[str, Any]:
        with self._condition:
            now = time.monotonic()
            self._set_pressure_state_locked(self._pressure_locked(), now)
            return {
                "high_water_events": self._high_events,
                "high_water_bytes": self._high_bytes,
                "seconds_throttled": self._throttled_seconds,
                "seconds_paused": self._paused_seconds,
                "write_failures": self._write_failures,
                "incomplete_events": self._incomplete_events,
                "dropped": self._dropped,
            }

    def close(self, timeout: float | None = None) -> None:
        with self._condition:
            if not self._closing:
                self._closing = True
                self._condition.notify_all()
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while self._outstanding_events:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError("timed out draining store writer")
                self._condition.wait(remaining)
        self._queue.put(None)
        remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
        self._thread.join(remaining)
        if self._thread.is_alive():
            raise TimeoutError("timed out stopping store writer")
        if self.run_id is not None and self._state == "degraded":
            self.store.mark_run_degraded(run_id=self.run_id)
        if self.run_id is not None:
            final_stats = self.stats()
            final_stats["incomplete_events"] = self.store.count_incomplete_events(run_id=self.run_id)
            self.store.update_queue_stats(run_id=self.run_id, stats=final_stats)
        if self._state == "degraded":
            raise AuditUnavailable(self._last_error or "writer is degraded")

