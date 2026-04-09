"""
Tests for detectors/finding_deduplicator.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from detectors.finding_deduplicator import (
    DeduplicatedFinding,
    DeduplicationReport,
    FindingDeduplicator,
    _combined_confidence,
    _fingerprint,
    _lines_overlap,
    _max_severity,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _finding(
    rule_id: str = "REGEX-001",
    file_path: str = "src/app.py",
    evidence: str = "AKIA1234567890",
    severity: str = "HIGH",
    confidence: float = 0.9,
    line_number: int = 10,
    detector: str = "regex_detector",
) -> dict:
    return {
        "rule_id": rule_id,
        "file_path": file_path,
        "evidence": evidence,
        "severity": severity,
        "confidence": confidence,
        "line_number": line_number,
        "detector": detector,
    }


def _entropy_finding(
    file_path: str = "src/app.py",
    evidence: str = "sk-abcdefghijklmnop",
    line_number: int = 10,
    confidence: float = 0.7,
) -> dict:
    return {
        "rule_id": "ENTROPY-001",
        "file_path": file_path,
        "evidence": evidence,
        "severity": "MEDIUM",
        "confidence": confidence,
        "line_number": line_number,
        "detector": "entropy_detector",
    }


# ===========================================================================
# Internal helpers
# ===========================================================================

class TestMaxSeverity:
    def test_single_critical(self):
        assert _max_severity(["CRITICAL"]) == "CRITICAL"

    def test_returns_highest(self):
        assert _max_severity(["LOW", "HIGH", "MEDIUM"]) == "HIGH"

    def test_empty_returns_unknown(self):
        assert _max_severity([]) == "UNKNOWN"

    def test_case_insensitive(self):
        assert _max_severity(["critical", "low"]) == "critical"


class TestCombinedConfidence:
    def test_single_confidence(self):
        assert _combined_confidence([0.5]) == pytest.approx(0.5, abs=0.01)

    def test_two_independent_detectors(self):
        # P(A ∪ B) = 1 - (1-0.5)(1-0.5) = 0.75
        result = _combined_confidence([0.5, 0.5])
        assert result == pytest.approx(0.75, abs=0.01)

    def test_empty_returns_zero(self):
        assert _combined_confidence([]) == 0.0

    def test_capped_at_one(self):
        assert _combined_confidence([1.0, 1.0]) <= 1.0

    def test_higher_than_any_single(self):
        c1 = _combined_confidence([0.6])
        c2 = _combined_confidence([0.6, 0.7])
        assert c2 >= c1


class TestLinesOverlap:
    def test_exact_same_line(self):
        assert _lines_overlap(10, 10, 10, 10, 0)

    def test_within_window(self):
        assert _lines_overlap(10, 10, 11, 11, 2)

    def test_outside_window(self):
        assert not _lines_overlap(10, 10, 20, 20, 2)

    def test_none_values(self):
        assert not _lines_overlap(None, 10, 10, 10, 2)

    def test_range_overlap(self):
        assert _lines_overlap(5, 15, 10, 20, 0)

    def test_adjacent_within_window(self):
        assert _lines_overlap(10, 10, 13, 13, 3)


class TestFingerprint:
    def test_deterministic(self):
        assert _fingerprint("R", "f", "e") == _fingerprint("R", "f", "e")

    def test_returns_64_chars(self):
        assert len(_fingerprint("R", "f", "e")) == 64

    def test_different_evidence(self):
        assert _fingerprint("R", "f", "e1") != _fingerprint("R", "f", "e2")


# ===========================================================================
# DeduplicatedFinding
# ===========================================================================

class TestDeduplicatedFinding:
    def _finding(self) -> DeduplicatedFinding:
        return DeduplicatedFinding(
            fingerprint="abc",
            rule_ids={"REGEX-001", "ENTROPY-001"},
            detectors={"regex_detector", "entropy_detector"},
            file_path="src/app.py",
            line_start=10,
            line_end=10,
            evidence="AKIA1234567890",
            severity="HIGH",
            confidence=0.95,
            source_count=2,
        )

    def test_primary_rule_id(self):
        f = self._finding()
        assert f.primary_rule_id in f.rule_ids

    def test_summary_contains_file_path(self):
        assert "src/app.py" in self._finding().summary()

    def test_to_dict_has_required_keys(self):
        d = self._finding().to_dict()
        for key in ("fingerprint", "rule_ids", "detectors", "file_path",
                    "severity", "confidence", "source_count"):
            assert key in d

    def test_rule_ids_sorted_in_dict(self):
        d = self._finding().to_dict()
        assert d["rule_ids"] == sorted(d["rule_ids"])


# ===========================================================================
# DeduplicationReport
# ===========================================================================

class TestDeduplicationReport:
    def _report(self) -> DeduplicationReport:
        f = DeduplicatedFinding(
            fingerprint="x",
            rule_ids={"R"},
            detectors={"d"},
            file_path="f",
            line_start=1,
            line_end=1,
            evidence="e",
            severity="HIGH",
            confidence=0.9,
        )
        return DeduplicationReport(
            deduplicated_findings=[f],
            input_count=3,
            output_count=1,
            merged_count=2,
        )

    def test_dedup_ratio(self):
        r = self._report()
        assert r.dedup_ratio == pytest.approx(2 / 3, abs=0.01)

    def test_summary_contains_counts(self):
        s = self._report().summary()
        assert "3" in s and "1" in s

    def test_by_severity_filter(self):
        r = self._report()
        high = r.by_severity("HIGH")
        assert len(high) == 1

    def test_by_file_filter(self):
        r = self._report()
        findings = r.by_file("f")
        assert len(findings) == 1

    def test_zero_input_dedup_ratio(self):
        r = DeduplicationReport(input_count=0)
        assert r.dedup_ratio == 0.0


# ===========================================================================
# FindingDeduplicator — no dedup needed
# ===========================================================================

class TestNoDedupNeeded:
    def test_empty_list_returns_empty_report(self):
        deduper = FindingDeduplicator()
        report = deduper.deduplicate([])
        assert report.input_count == 0
        assert report.output_count == 0

    def test_different_files_not_merged(self):
        deduper = FindingDeduplicator()
        findings = [
            _finding(file_path="src/a.py"),
            _finding(file_path="src/b.py"),
        ]
        report = deduper.deduplicate(findings)
        assert report.output_count == 2
        assert report.merged_count == 0

    def test_different_rule_ids_and_nonoverlapping_lines_not_merged(self):
        deduper = FindingDeduplicator(overlap_window=0)
        findings = [
            _finding(rule_id="REGEX-001", line_number=5),
            _finding(rule_id="REGEX-002", line_number=100),
        ]
        report = deduper.deduplicate(findings)
        assert report.output_count == 2


# ===========================================================================
# FindingDeduplicator — same rule_id
# ===========================================================================

class TestSameRuleIdMerge:
    def test_same_rule_same_file_merged(self):
        deduper = FindingDeduplicator()
        findings = [
            _finding(rule_id="REGEX-001", detector="regex_detector"),
            _finding(rule_id="REGEX-001", detector="ci_scanner"),
        ]
        report = deduper.deduplicate(findings)
        assert report.output_count == 1
        assert report.merged_count == 1

    def test_merged_detectors_union(self):
        deduper = FindingDeduplicator()
        findings = [
            _finding(detector="regex_detector"),
            _finding(detector="entropy_detector"),
        ]
        report = deduper.deduplicate(findings)
        f = report.deduplicated_findings[0]
        assert "regex_detector" in f.detectors
        assert "entropy_detector" in f.detectors

    def test_merged_confidence_is_probability_union(self):
        deduper = FindingDeduplicator()
        findings = [
            _finding(confidence=0.6, detector="d1"),
            _finding(confidence=0.6, detector="d2"),
        ]
        report = deduper.deduplicate(findings)
        merged_conf = report.deduplicated_findings[0].confidence
        # P(A ∪ B) = 1 - (1-0.6)^2 = 0.84
        assert merged_conf == pytest.approx(0.84, abs=0.01)

    def test_merged_source_count(self):
        deduper = FindingDeduplicator()
        findings = [_finding() for _ in range(3)]
        report = deduper.deduplicate(findings)
        assert report.deduplicated_findings[0].source_count == 3


# ===========================================================================
# FindingDeduplicator — line overlap
# ===========================================================================

class TestLineOverlapMerge:
    def test_adjacent_lines_merged_within_window(self):
        deduper = FindingDeduplicator(overlap_window=2)
        findings = [
            _finding(rule_id="E-001", line_number=10),
            _finding(rule_id="R-001", line_number=11),
        ]
        report = deduper.deduplicate(findings)
        assert report.output_count == 1

    def test_distant_lines_not_merged(self):
        deduper = FindingDeduplicator(overlap_window=2)
        findings = [
            _finding(rule_id="E-001", line_number=10),
            _finding(rule_id="R-001", line_number=50),
        ]
        report = deduper.deduplicate(findings)
        assert report.output_count == 2

    def test_merged_line_range_spans_all(self):
        deduper = FindingDeduplicator(overlap_window=5)
        findings = [
            _finding(rule_id="A", line_number=5),
            _finding(rule_id="B", line_number=8),
        ]
        report = deduper.deduplicate(findings)
        f = report.deduplicated_findings[0]
        assert f.line_start == 5
        assert f.line_end == 8


# ===========================================================================
# FindingDeduplicator — fingerprint match
# ===========================================================================

class TestFingerprintMatch:
    def test_same_fingerprint_merged(self):
        deduper = FindingDeduplicator(overlap_window=0)
        fp = "a" * 64
        findings = [
            {"rule_id": "A", "file_path": "f.py", "fingerprint": fp, "line_number": 1},
            {"rule_id": "B", "file_path": "f.py", "fingerprint": fp, "line_number": 999},
        ]
        report = deduper.deduplicate(findings)
        assert report.output_count == 1


# ===========================================================================
# FindingDeduplicator — severity and evidence
# ===========================================================================

class TestSeverityAndEvidence:
    def test_max_severity_selected(self):
        deduper = FindingDeduplicator()
        findings = [
            _finding(severity="LOW"),
            _finding(severity="CRITICAL"),
        ]
        report = deduper.deduplicate(findings)
        assert report.deduplicated_findings[0].severity in ("CRITICAL", "critical")

    def test_longest_evidence_selected(self):
        deduper = FindingDeduplicator()
        findings = [
            _finding(evidence="short"),
            _finding(evidence="a much longer evidence string"),
        ]
        report = deduper.deduplicate(findings)
        assert report.deduplicated_findings[0].evidence == "a much longer evidence string"


# ===========================================================================
# FindingDeduplicator — suppressed
# ===========================================================================

class TestSuppressedMerge:
    def test_all_suppressed_merged_is_suppressed(self):
        deduper = FindingDeduplicator()
        findings = [
            {**_finding(), "suppressed": True},
            {**_finding(), "suppressed": True},
        ]
        report = deduper.deduplicate(findings)
        assert report.deduplicated_findings[0].suppressed is True

    def test_any_unsuppressed_merged_is_not_suppressed(self):
        deduper = FindingDeduplicator()
        findings = [
            {**_finding(), "suppressed": True},
            {**_finding(), "suppressed": False},
        ]
        report = deduper.deduplicate(findings)
        assert report.deduplicated_findings[0].suppressed is False

    def test_suppressed_count_in_report(self):
        deduper = FindingDeduplicator()
        findings = [
            {**_finding(file_path="a.py"), "suppressed": True},
            {**_finding(file_path="b.py"), "suppressed": False},
        ]
        report = deduper.deduplicate(findings)
        assert report.suppressed_count == 1
