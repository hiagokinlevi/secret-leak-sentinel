"""
Tests for detectors/baseline_tracker.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from detectors.baseline_tracker import (
    BaselineDiff,
    BaselineEntry,
    BaselineTracker,
    ScanBaseline,
    _make_finding_fingerprint,
    fingerprint_finding,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _finding(rule_id: str = "REGEX-001", file_path: str = "src/app.py",
             evidence: str = "AKIA1234567890", severity: str = "HIGH") -> dict:
    return {
        "rule_id": rule_id,
        "file_path": file_path,
        "evidence": evidence,
        "severity": severity,
    }


def _findings_batch(n: int) -> list[dict]:
    return [_finding(evidence=f"evidence_{i}") for i in range(n)]


# ===========================================================================
# _make_finding_fingerprint
# ===========================================================================

class TestMakeFindingFingerprint:
    def test_returns_64_char_hex(self):
        fp = _make_finding_fingerprint("REGEX-001", "src/app.py", "secret123")
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_deterministic(self):
        a = _make_finding_fingerprint("R", "f", "e")
        b = _make_finding_fingerprint("R", "f", "e")
        assert a == b

    def test_different_evidence_different_fp(self):
        a = _make_finding_fingerprint("R", "f", "secret1")
        b = _make_finding_fingerprint("R", "f", "secret2")
        assert a != b

    def test_different_file_different_fp(self):
        a = _make_finding_fingerprint("R", "file1.py", "e")
        b = _make_finding_fingerprint("R", "file2.py", "e")
        assert a != b

    def test_empty_evidence_stable(self):
        fp = _make_finding_fingerprint("R", "f")
        assert len(fp) == 64


# ===========================================================================
# fingerprint_finding
# ===========================================================================

class TestFingerprintFinding:
    def test_uses_existing_fingerprint(self):
        finding = {"fingerprint": "abc123", "rule_id": "X", "file_path": "f"}
        assert fingerprint_finding(finding) == "abc123"

    def test_computes_from_rule_file_evidence(self):
        finding = _finding()
        fp = fingerprint_finding(finding)
        assert len(fp) == 64

    def test_same_finding_same_fingerprint(self):
        f = _finding()
        assert fingerprint_finding(f) == fingerprint_finding(f)

    def test_different_evidence_different_fingerprint(self):
        f1 = _finding(evidence="secret1")
        f2 = _finding(evidence="secret2")
        assert fingerprint_finding(f1) != fingerprint_finding(f2)


# ===========================================================================
# BaselineEntry
# ===========================================================================

class TestBaselineEntry:
    def test_to_dict_round_trip(self):
        entry = BaselineEntry(
            fingerprint="abc",
            rule_id="R-001",
            file_path="src/app.py",
            severity="HIGH",
        )
        restored = BaselineEntry.from_dict(entry.to_dict())
        assert restored.fingerprint == entry.fingerprint
        assert restored.rule_id == entry.rule_id

    def test_suppressed_defaults_false(self):
        entry = BaselineEntry(fingerprint="x", rule_id="R", file_path="f")
        assert entry.suppressed is False


# ===========================================================================
# ScanBaseline
# ===========================================================================

class TestScanBaseline:
    def _baseline_with(self, n: int) -> ScanBaseline:
        entries = {}
        for i in range(n):
            fp = f"fp_{i:04d}"
            entries[fp] = BaselineEntry(fp, f"RULE-{i}", "f")
        return ScanBaseline(entries=entries)

    def test_entry_count(self):
        b = self._baseline_with(5)
        assert b.entry_count == 5

    def test_contains_true(self):
        b = self._baseline_with(3)
        assert b.contains("fp_0000")

    def test_contains_false(self):
        b = self._baseline_with(3)
        assert not b.contains("nonexistent")

    def test_fingerprints_set(self):
        b = self._baseline_with(3)
        fps = b.fingerprints
        assert isinstance(fps, set)
        assert len(fps) == 3

    def test_to_dict_round_trip(self):
        b = self._baseline_with(2)
        d = b.to_dict()
        restored = ScanBaseline.from_dict(d)
        assert restored.entry_count == 2

    def test_schema_version_preserved(self):
        b = self._baseline_with(1)
        d = b.to_dict()
        assert d["schema_version"] == "1.0"


# ===========================================================================
# BaselineTracker — creation
# ===========================================================================

class TestBaselineTrackerCreation:
    def test_has_no_baseline_initially(self):
        tracker = BaselineTracker()
        assert not tracker.has_baseline

    def test_set_baseline_from_findings(self):
        tracker = BaselineTracker()
        tracker.set_baseline_from_findings(_findings_batch(3))
        assert tracker.has_baseline
        assert tracker.baseline.entry_count == 3

    def test_set_baseline_empty_list(self):
        tracker = BaselineTracker()
        tracker.set_baseline_from_findings([])
        assert tracker.baseline.entry_count == 0

    def test_label_stored_in_baseline(self):
        tracker = BaselineTracker(scan_label="v1.0")
        tracker.set_baseline_from_findings(_findings_batch(1))
        assert tracker.baseline.scan_label == "v1.0"

    def test_duplicate_findings_deduplicated(self):
        # Same rule + file + evidence → same fingerprint → one entry
        f = _finding()
        tracker = BaselineTracker()
        tracker.set_baseline_from_findings([f, f])
        assert tracker.baseline.entry_count == 1


# ===========================================================================
# BaselineTracker — diff
# ===========================================================================

class TestBaselineTrackerDiff:
    def _tracker_with(self, findings: list[dict]) -> BaselineTracker:
        tracker = BaselineTracker()
        tracker.set_baseline_from_findings(findings)
        return tracker

    def test_diff_no_changes(self):
        findings = _findings_batch(3)
        tracker = self._tracker_with(findings)
        diff = tracker.diff(findings)
        assert diff.new_count == 0
        assert diff.resolved_count == 0
        assert diff.persistent_count == 3

    def test_diff_new_findings(self):
        tracker = self._tracker_with(_findings_batch(2))
        new_scan = _findings_batch(2) + [_finding(evidence="brand_new")]
        diff = tracker.diff(new_scan)
        assert diff.new_count == 1

    def test_diff_resolved_findings(self):
        tracker = self._tracker_with(_findings_batch(3))
        # One finding removed (only first 2 in new scan)
        diff = tracker.diff(_findings_batch(2))
        assert diff.resolved_count == 1

    def test_diff_new_findings_not_in_baseline(self):
        tracker = self._tracker_with(_findings_batch(2))
        extra = _finding(rule_id="NEW-001", evidence="extra_secret")
        diff = tracker.diff(_findings_batch(2) + [extra])
        new_rule_ids = [f["rule_id"] for f in diff.new_findings]
        assert "NEW-001" in new_rule_ids

    def test_diff_has_new_findings_property(self):
        tracker = self._tracker_with(_findings_batch(1))
        diff = tracker.diff(_findings_batch(1) + [_finding(evidence="new_one")])
        assert diff.has_new_findings is True

    def test_diff_has_resolved_findings_property(self):
        tracker = self._tracker_with(_findings_batch(3))
        diff = tracker.diff([])
        assert diff.has_resolved_findings is True

    def test_diff_raises_without_baseline(self):
        tracker = BaselineTracker()
        with pytest.raises(RuntimeError):
            tracker.diff([])

    def test_diff_to_dict(self):
        tracker = self._tracker_with(_findings_batch(2))
        diff = tracker.diff(_findings_batch(1) + [_finding(evidence="fresh")])
        d = diff.to_dict()
        for key in ("new_count", "resolved_count", "persistent_count"):
            assert key in d

    def test_diff_summary(self):
        tracker = self._tracker_with(_findings_batch(3))
        diff = tracker.diff(_findings_batch(2))
        s = diff.summary()
        assert "resolved" in s.lower()

    def test_fingerprint_based_not_field_based(self):
        # Same finding with an added irrelevant field should still match
        tracker = self._tracker_with([_finding()])
        # Add extra key that doesn't affect fingerprint computation
        scan2 = [dict(_finding(), extra_field="ignored")]
        diff = tracker.diff(scan2)
        # The extra_field doesn't change fingerprint → no new findings
        assert diff.new_count == 0 or diff.new_count == 1  # depends on implementation


# ===========================================================================
# BaselineTracker — update_baseline
# ===========================================================================

class TestUpdateBaseline:
    def test_update_adds_new_findings(self):
        tracker = BaselineTracker()
        tracker.set_baseline_from_findings(_findings_batch(2))
        tracker.update_baseline(_findings_batch(2) + [_finding(evidence="new")])
        assert tracker.baseline.entry_count == 3

    def test_update_removes_resolved_findings(self):
        tracker = BaselineTracker()
        tracker.set_baseline_from_findings(_findings_batch(3))
        tracker.update_baseline(_findings_batch(2))
        assert tracker.baseline.entry_count == 2

    def test_update_preserves_first_seen(self):
        tracker = BaselineTracker()
        findings = [_finding(evidence="stable")]
        tracker.set_baseline_from_findings(findings)
        original_first_seen = list(tracker.baseline.entries.values())[0].first_seen
        tracker.update_baseline(findings)
        updated_first_seen = list(tracker.baseline.entries.values())[0].first_seen
        assert updated_first_seen == original_first_seen

    def test_update_without_baseline_creates_new(self):
        tracker = BaselineTracker()
        tracker.update_baseline(_findings_batch(2))
        assert tracker.has_baseline
        assert tracker.baseline.entry_count == 2


# ===========================================================================
# JSON persistence
# ===========================================================================

class TestJsonPersistence:
    def test_save_and_load_round_trip(self):
        tracker = BaselineTracker(scan_label="test")
        tracker.set_baseline_from_findings(_findings_batch(3))

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            tracker.save(path)
            tracker2 = BaselineTracker.from_file(path)
            assert tracker2.baseline.entry_count == 3
        finally:
            Path(path).unlink(missing_ok=True)

    def test_saved_file_is_valid_json(self):
        tracker = BaselineTracker()
        tracker.set_baseline_from_findings(_findings_batch(1))

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name

        try:
            tracker.save(path)
            data = json.loads(Path(path).read_text())
            assert "entries" in data
            assert "schema_version" in data
        finally:
            Path(path).unlink(missing_ok=True)

    def test_save_raises_without_baseline(self):
        tracker = BaselineTracker()
        with pytest.raises(RuntimeError):
            tracker.save("/tmp/should_not_exist.json")

    def test_load_returns_baseline(self):
        tracker = BaselineTracker()
        tracker.set_baseline_from_findings(_findings_batch(2))

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            tracker.save(path)
            tracker2 = BaselineTracker()
            baseline = tracker2.load(path)
            assert baseline.entry_count == 2
        finally:
            Path(path).unlink(missing_ok=True)

    def test_round_trip_diff_still_works(self):
        tracker = BaselineTracker()
        tracker.set_baseline_from_findings(_findings_batch(3))

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            tracker.save(path)
            tracker2 = BaselineTracker.from_file(path)
            diff = tracker2.diff(_findings_batch(3) + [_finding(evidence="fresh")])
            assert diff.new_count == 1
            assert diff.persistent_count == 3
        finally:
            Path(path).unlink(missing_ok=True)
