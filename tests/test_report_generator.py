"""
Tests for reports.report_generator.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from detectors.entropy_detector import EntropyFinding
from reports.report_generator import generate_scan_report


def _make_entropy(file_path: str = "config.py", line_number: int = 3) -> EntropyFinding:
    return EntropyFinding(
        file_path=file_path,
        line_number=line_number,
        token="aB3x****[36chars]",
        entropy=4.87,
        masked_excerpt='token = "aB3x****[36chars]"',
        confidence=0.72,
        token_fingerprint="shared-token-fp",
    )


def test_entropy_only_report_is_not_marked_clean() -> None:
    report = generate_scan_report(
        [],
        scan_path="repo",
        entropy_findings=[_make_entropy()],
    )

    assert "No secrets detected" not in report
    assert "## Entropy Findings" in report
    assert "`config.py`" in report


def test_empty_report_still_returns_clean_banner() -> None:
    report = generate_scan_report([], scan_path="repo", entropy_findings=[])

    assert "No secrets detected" in report
