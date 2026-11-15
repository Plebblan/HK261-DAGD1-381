"""Budget and rate-limit helpers for gateway evaluation."""

from __future__ import annotations


DEFAULT_BUDGETS = {
    "max_requests_per_run": 5000,
    "rate_per_second": 10,
    "max_concurrency": 2,
}
