import importlib.util
import json
import sys
from pathlib import Path

import pytest

RUNTRACE_PATH = Path(__file__).resolve().parents[1] / "lab-apps/custom/app/runtrace.py"
SPEC = importlib.util.spec_from_file_location("custom_runtrace", RUNTRACE_PATH)
RUNTRACE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = RUNTRACE
SPEC.loader.exec_module(RUNTRACE)
_resolve_run_id = RUNTRACE._resolve_run_id


def test_runtrace_uses_proxy_run_metadata(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "run.json").write_text(json.dumps({"run_id": "proxy-owned-id"}), encoding="utf-8")
    assert _resolve_run_id(None, run_dir, dry_run=False) == "proxy-owned-id"


def test_runtrace_rejects_mismatched_explicit_id(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "run.json").write_text(json.dumps({"run_id": "proxy-owned-id"}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="Run ID mismatch"):
        _resolve_run_id("other-id", run_dir, dry_run=False)


def test_runtrace_requires_id_for_non_dry_run(tmp_path, monkeypatch):
    monkeypatch.delenv("RUNTRACE_RUN_ID", raising=False)
    with pytest.raises(RuntimeError, match="shared proxy run ID is required"):
        _resolve_run_id(None, tmp_path / "missing-run-dir", dry_run=False)


def test_runtrace_rejects_malformed_proxy_run_metadata(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "run.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Cannot read proxy run metadata"):
        _resolve_run_id(None, run_dir, dry_run=False)
