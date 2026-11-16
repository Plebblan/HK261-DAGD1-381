"""Per-target, per-component system logging."""

from __future__ import annotations

import contextvars
import logging
import re
import threading
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Iterator, Mapping

from .redaction import redact_log_text

_run_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("log_run_id", default=None)
_event_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("log_event_id", default=None)
_operation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "log_operation_id", default=None
)
_handlers: dict[tuple[str, str], RotatingFileHandler] = {}
_lock = threading.RLock()
_COMPONENT_NAME = re.compile(r"[A-Za-z0-9_-]+\Z")


class _RedactionContextFilter(logging.Filter):
    def __init__(self, run_id: str | None):
        super().__init__()
        self.run_id = run_id

    def filter(self, record: logging.LogRecord) -> bool:
        record.run_id = getattr(record, "run_id", None) or _run_id.get() or self.run_id or "-"
        record.event_id = getattr(record, "event_id", None) or _event_id.get() or "-"
        record.operation_id = (
            getattr(record, "operation_id", None) or _operation_id.get() or "-"
        )

        record.msg = redact_log_text(record.getMessage())
        record.args = ()
        if record.exc_info:
            record.exc_text = redact_log_text(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = redact_log_text(record.exc_text)
        return True


@contextmanager
def log_context(
    *,
    run_id: str | None = None,
    event_id: str | None = None,
    operation_id: str | None = None,
) -> Iterator[None]:
    """Attach identifiers to log records emitted within the context."""
    tokens = []
    for variable, value in (
        (_run_id, run_id),
        (_event_id, event_id),
        (_operation_id, operation_id),
    ):
        if value is not None:
            tokens.append((variable, variable.set(value)))
    try:
        yield
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)


def configure_component_logging(
    log_dir: str | Path,
    *,
    component: str,
    run_id: str | None = None,
    config: Mapping[str, Any] | None = None,
    reset: bool = False,
    logger_name: str | None = None,
) -> logging.Logger:
    """Configure a rotating component log under the target's ``logs`` folder.

    ``config`` may be either the full gateway configuration or its ``logging``
    section. Set ``reset`` at the start of a new run to clear prior run files.
    """
    if not _COMPONENT_NAME.fullmatch(component):
        raise ValueError("component must contain only letters, digits, '_' or '-'")
    if run_id is not None and (not run_id.strip() or "\n" in run_id or "\r" in run_id):
        raise ValueError("run_id must be a non-empty single-line value")
    if reset and run_id is None:
        raise ValueError("run_id is required when resetting logs for a new run")

    settings: Mapping[str, Any] = config or {}
    nested = settings.get("logging")
    if isinstance(nested, Mapping):
        settings = nested
    level = settings.get("level", "INFO")
    if isinstance(level, str):
        level = logging.getLevelName(level.upper())
    if not isinstance(level, int) or level < 0:
        raise ValueError("logging.level must be a valid logging level")
    max_bytes = settings.get("max_bytes_per_file", 10_485_760)
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("logging.max_bytes_per_file must be a positive integer")

    directory = Path(log_dir)
    directory.mkdir(parents=True, exist_ok=True)
    normalized_dir = str(directory.resolve())
    logger_name = logger_name or f"src.{component}"
    logger = logging.getLogger(logger_name)
    key = (normalized_dir, logger_name)

    with _lock:
        if reset:
            for existing_key, handler in list(_handlers.items()):
                if existing_key[0] == normalized_dir:
                    existing_logger = logging.getLogger(existing_key[1])
                    existing_logger.removeHandler(handler)
                    handler.close()
                    del _handlers[existing_key]
            for child in directory.iterdir():
                if child.is_file() or child.is_symlink():
                    child.unlink()
            (directory / "run_id.txt").write_text(f"{run_id}\n", encoding="utf-8")
        elif run_id is not None:
            (directory / "run_id.txt").write_text(f"{run_id}\n", encoding="utf-8")

        handler = _handlers.get(key)
        if handler is None:
            handler = RotatingFileHandler(
                directory / f"{component}.log",
                maxBytes=max_bytes,
                backupCount=3,
                encoding="utf-8",
            )
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)s run_id=%(run_id)s "
                    "event_id=%(event_id)s operation_id=%(operation_id)s %(message)s"
                )
            )
            _handlers[key] = handler
            logger.addHandler(handler)
        handler.setLevel(level)
        handler.filters.clear()
        handler.addFilter(_RedactionContextFilter(run_id))
        logger.setLevel(level)
        logger.propagate = False
    return logger
