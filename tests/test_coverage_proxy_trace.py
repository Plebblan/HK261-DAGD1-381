from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_coverage_accepts_shared_store_trace_jsonl(tmp_path):
    trace = tmp_path / "trace.jsonl"
    trace.write_text("", encoding="utf-8")
    report_path = tmp_path / "coverage.json"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "lab-apps/custom_1/cyber-range/coverage.py"),
            "--log", str(trace),
            "--out", str(report_path),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["metrics_version"] == "1.1"
    assert report["n_events"] == 0
    assert report["forwarded_events"] == 0
    assert report["overall"]["gateway_denials"] == 0
