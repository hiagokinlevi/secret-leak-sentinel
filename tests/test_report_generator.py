from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from classifiers.criticality_classifier import ClassifiedFinding
from detectors.entropy_detector import EntropyFinding
from detectors.regex_detector import Criticality, Finding, SecretType
from reports.report_generator import generate_scan_report


def _classified() -> ClassifiedFinding:
    finding = Finding(
        detector_name="generic_secret_assignment",
        secret_type=SecretType.GENERIC_SECRET,
        criticality=Criticality.MEDIUM,
        file_path="src/app.py",
        line_number=12,
        masked_excerpt='secret = "aB3x****[36chars]"',
        confidence=0.65,
    )
    return ClassifiedFinding(
        original_finding=finding,
        final_criticality=Criticality.MEDIUM,
        confidence=0.65,
        rationale="Test rationale.",
        entropy_corroboration=False,
        context_penalty=False,
        context_escalation=False,
    )


def _entropy(file_path: str = "config.py", line_number: int = 3) -> EntropyFinding:
    return EntropyFinding(
        file_path=file_path,
        line_number=line_number,
        token="aB3x****[36chars]",
        entropy=5.05,
        masked_excerpt='secret = "aB3x****[36chars]"',
        confidence=0.74,
        token_fingerprint="shared-fingerprint",
    )


def test_entropy_only_report_is_not_marked_clean() -> None:
    report = generate_scan_report(
        [],
        scan_path="repo",
        entropy_findings=[_entropy()],
    )

    assert "No secrets detected" not in report
    assert "## Entropy Findings" in report
    assert "`config.py`" in report


def test_empty_report_still_returns_clean_banner() -> None:
    report = generate_scan_report([], scan_path="repo", entropy_findings=[])

    assert "No secrets detected" in report


def test_generate_scan_report_includes_cross_file_correlation_section() -> None:
    report = generate_scan_report(
        [_classified()],
        scan_path=".",
        entropy_findings=[
            _entropy("src/app.py", 12),
            _entropy("deploy/.env", 4),
        ],
    )

    assert "Cross-File Correlated Entropy Tokens" in report
    assert "shared-finge" in report
    assert "`src/app.py`" in report
    assert "`deploy/.env`" in report

