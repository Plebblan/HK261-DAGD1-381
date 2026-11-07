"""custom_1 (TenantDesk + ShopFlow): replay the taxonomy-based ground truth and check artifact consistency.

Run from the repository root:  pytest tests
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

RANGE = Path(__file__).resolve().parents[1] / "lab-apps" / "custom_1" / "cyber-range"
spec = importlib.util.spec_from_file_location("replay_ground_truth", RANGE / "replay_ground_truth.py")
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)

CASES = replay.GT["cases"]


def _payload(r):
    try:
        return r.json()
    except Exception:
        return None


@pytest.mark.parametrize("case", [c for c in CASES if not c["is_benign"]], ids=lambda c: c["case_id"])
def test_planted_case_fires_only_when_enabled(case):
    r = replay.run(case, [case["flag"]])
    assert replay.vulnerable(case["vulnerable_if"], r.status_code, _payload(r)), f"{case['flag']} did not fire: {r.status_code} {r.text}"
    r = replay.run(case, [])
    assert r.status_code in case["expected_safe_status"], f"patched twin returned {r.status_code}"
    assert not replay.vulnerable(case["vulnerable_if"], r.status_code, _payload(r)), "patched twin still vulnerable"


@pytest.mark.parametrize("mode", ["patched", "all-flaws-on"])
@pytest.mark.parametrize("case", [c for c in CASES if c["is_benign"]], ids=lambda c: c["case_id"])
def test_benign_case_is_safe(case, mode):
    flaws = [] if mode == "patched" else importlib_flaws(case["app"])
    r = replay.run(case, flaws)
    assert r.status_code in case["expected_safe_status"]


def importlib_flaws(app):
    import importlib
    return importlib.import_module(f"custom_1.{app}").FLAWS


def test_artifacts_are_consistent():
    p = subprocess.run([sys.executable, str(RANGE / "validate_custom.py")], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr
