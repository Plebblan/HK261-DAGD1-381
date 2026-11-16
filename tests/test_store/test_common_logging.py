import logging
import sqlite3

from src.common.logging import configure_component_logging, log_context
from src.store.store import Store


def test_component_logging_routes_redacts_and_resets_by_run(tmp_path):
    log_dir = tmp_path / "runs" / "sample" / "logs"
    logger_name = "test.store.logging"
    logger = configure_component_logging(
        log_dir,
        component="store",
        run_id="run-1",
        config={"logging": {"level": "DEBUG", "max_bytes_per_file": 4096}},
        reset=True,
        logger_name=logger_name,
    )
    with log_context(event_id="event-1", operation_id="op-1"):
        logger.error("Authorization: Bearer abc123 Cookie: session=private; auth=private-too")
        logger.error("\"request_body\":{\"token\":\"secret-value\"}")

    log_file = log_dir / "store.log"
    content = log_file.read_text(encoding="utf-8")
    assert "run_id=run-1" in content
    assert "event_id=event-1" in content
    assert "operation_id=op-1" in content
    assert "[REDACTED]" in content
    assert "abc123" not in content
    assert "private" not in content
    assert "secret-value" not in content
    assert (log_dir / "run_id.txt").read_text(encoding="utf-8").strip() == "run-1"

    logger.info("previous run entry")
    configure_component_logging(
        log_dir,
        component="store",
        run_id="run-2",
        reset=True,
        logger_name=logger_name,
    )
    assert "previous run entry" not in log_file.read_text(encoding="utf-8")
    assert (log_dir / "run_id.txt").read_text(encoding="utf-8").strip() == "run-2"


def test_component_logging_rotates_files(tmp_path):
    log_dir = tmp_path / "logs"
    logger = configure_component_logging(
        log_dir,
        component="gateway",
        run_id="run-rotation",
        config={"level": "DEBUG", "max_bytes_per_file": 100},
        reset=True,
        logger_name="test.gateway.logging",
    )
    for index in range(10):
        logger.debug("message-%s-%s", index, "x" * 40)

    assert (log_dir / "gateway.log").exists()
    assert (log_dir / "gateway.log.1").exists()


def test_store_routes_database_failures_to_target_log(tmp_path):
    database_path = tmp_path / "runs" / "sample" / "store.db"
    store = Store(database_path)
    try:
        store.create_run(run_id="run-store")
        store.append_event(
            event_id="event-1",
            run_id="run-store",
            operation_id="operation-1",
        )
        try:
            store.append_event(
                event_id="event-1",
                run_id="run-store",
                operation_id="operation-1",
            )
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("duplicate event ID should fail")
    finally:
        store.close()

    log_file = database_path.parent / "logs" / "store.log"
    content = log_file.read_text(encoding="utf-8")
    assert "run_id=run-store" in content
    assert "event_id=event-1" in content
    assert "operation_id=operation-1" in content

