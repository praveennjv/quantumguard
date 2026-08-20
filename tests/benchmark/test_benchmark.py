import time
from pathlib import Path

from scanner.analyzers.engine import scan_path

ROOT = Path(__file__).resolve().parents[2]


def test_scan_speed_fixture_tree():
    start = time.perf_counter()
    result = scan_path(ROOT / "tests")
    elapsed = time.perf_counter() - start
    assert elapsed < 30
    assert result.stats["files"] >= 1
