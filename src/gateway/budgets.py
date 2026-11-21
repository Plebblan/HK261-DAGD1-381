<<<<<<< Updated upstream
"""Budget and rate-limit helpers for gateway evaluation."""

from __future__ import annotations


DEFAULT_BUDGETS = {
    "max_requests_per_run": 5000,
    "rate_per_second": 10,
    "max_concurrency": 2,
}
=======
"""Budgets: per-run request cap, rate, concurrency, and writer backpressure.

``check_budgets`` is pure over a :class:`Counters` snapshot. The mutable part is
:class:`BudgetTracker`, which the stateful ``Gateway`` wrapper owns.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class BudgetLimits:
    max_requests_per_run: int = 5000
    rate_per_second: float = 10
    max_concurrency: int = 2
    throttle_threshold: float = 0.5
    pause_threshold: float = 0.9

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> "BudgetLimits":
        budgets, store = config["budgets"], config["store"]
        return cls(
            max_requests_per_run=budgets["max_requests_per_run"],
            rate_per_second=budgets["rate_per_second"],
            max_concurrency=budgets["max_concurrency"],
            throttle_threshold=store["throttle_threshold"],
            pause_threshold=store["pause_threshold"],
        )


@dataclass(frozen=True)
class Counters:
    """Immutable snapshot of run state read by the engine."""

    requests_in_run: int = 0
    in_flight: int = 0
    requests_last_second: int = 0
    writer_pressure: float = 0.0      # StoreWriter.health().pressure, 0..1
    writer_healthy: bool = True


@dataclass(frozen=True)
class BudgetResult:
    ok: bool
    detail: str | None = None         # request_cap | rate | concurrency | writer_paused | audit_unavailable
    retry_after_s: float | None = None


def effective_rate(limits: BudgetLimits, pressure: float) -> float:
    """Scale the rate budget down between the throttle and pause thresholds."""
    if pressure < limits.throttle_threshold:
        return limits.rate_per_second
    span = max(limits.pause_threshold - limits.throttle_threshold, 1e-9)
    scale = max(0.1, 1.0 - (pressure - limits.throttle_threshold) / span)
    return limits.rate_per_second * scale


def check_budgets(limits: BudgetLimits, counters: Counters) -> BudgetResult:
    if not counters.writer_healthy:
        return BudgetResult(False, "audit_unavailable")      # fail closed
    if counters.requests_in_run >= limits.max_requests_per_run:
        return BudgetResult(False, "request_cap")
    if counters.writer_pressure >= limits.pause_threshold:
        return BudgetResult(False, "writer_paused", 0.05)
    if counters.in_flight >= limits.max_concurrency:
        return BudgetResult(False, "concurrency", 0.01)
    rate = effective_rate(limits, counters.writer_pressure)
    if counters.requests_last_second >= max(1, int(rate)):
        return BudgetResult(False, "rate", 1.0 / max(rate, 0.1))
    return BudgetResult(True)


class BudgetTracker:
    """Thread-safe counters behind :class:`Counters` snapshots."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.RLock()
        self._total = 0
        self._in_flight = 0
        self._recent: deque[float] = deque()

    def snapshot(self, *, writer_pressure: float = 0.0, writer_healthy: bool = True) -> Counters:
        with self._lock:
            return self._snapshot_locked(writer_pressure, writer_healthy)

    def _snapshot_locked(self, pressure: float, healthy: bool) -> Counters:
        now = self._clock()
        while self._recent and now - self._recent[0] >= 1.0:
            self._recent.popleft()
        return Counters(self._total, self._in_flight, len(self._recent), pressure, healthy)

    def reserve(self, *, concurrent: bool = True) -> None:
        with self._lock:
            self._total += 1
            self._recent.append(self._clock())
            if concurrent:
                self._in_flight += 1

    def release(self) -> None:
        with self._lock:
            self._in_flight = max(0, self._in_flight - 1)

    def lock(self) -> "threading.RLock":
        return self._lock
>>>>>>> Stashed changes
