"""
Tests for detectors/suppression.py — SuppressionRule, SuppressionStore, audit.
"""
from __future__ import annotations

import json
import sys
import tempfile
from datetime import date, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from detectors.suppression import (
    SuppressionAuditReport,
    SuppressionRule,
    SuppressionStore,
    make_fingerprint,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _past(days: int) -> str:
    return (date.today() - timedelta(days=days)).isoformat()


def _future(days: int) -> str:
    return (date.today() + timedelta(days=days)).isoformat()


def _rule(**kwargs) -> SuppressionRule:
    defaults = {
        "rule_id": "REGEX-001",
        "file_path": "tests/fixtures/test_data.py",
        "reason": "Test fixture — not a real secret",
        "owner": "security@example.com",
    }
    defaults.update(kwargs)
    return SuppressionRule(**defaults)


# ===========================================================================
# SuppressionRule
# ===========================================================================

class TestSuppressionRule:
    def test_requires_non_empty_reason(self):
        with pytest.raises(ValueError, match="reason"):
            SuppressionRule(rule_id="X", file_path="f", reason="")

    def test_suppression_id_auto_generated(self):
        rule = _rule()
        assert len(rule.suppression_id) == 16

    def test_suppression_id_stable(self):
        rule1 = _rule()
        rule2 = _rule()
        assert rule1.suppression_id == rule2.suppression_id

    def test_not_expired_with_future_date(self):
        rule = _rule(expires=_future(30))
        assert not rule.is_expired

    def test_expired_with_past_date(self):
        rule = _rule(expires=_past(1))
        assert rule.is_expired

    def test_not_expired_with_no_expiry(self):
        rule = _rule(expires=None)
        assert not rule.is_expired

    def test_is_permanent_when_no_expiry(self):
        assert _rule(expires=None).is_permanent

    def test_not_permanent_when_expiry_set(self):
        assert not _rule(expires=_future(30)).is_permanent

    def test_days_until_expiry_positive(self):
        rule = _rule(expires=_future(30))
        days = rule.days_until_expiry
        assert days is not None
        assert 28 <= days <= 31  # allow ±1 day for test timing

    def test_days_until_expiry_negative_for_expired(self):
        rule = _rule(expires=_past(5))
        days = rule.days_until_expiry
        assert days is not None
        assert days < 0

    def test_days_until_expiry_none_for_permanent(self):
        assert _rule(expires=None).days_until_expiry is None

    def test_to_dict_round_trip(self):
        rule = _rule(expires=_future(30))
        d = rule.to_dict()
        restored = SuppressionRule.from_dict(d)
        assert restored.rule_id == rule.rule_id
        assert restored.file_path == rule.file_path


# ===========================================================================
# SuppressionStore — CRUD
# ===========================================================================

class TestSuppressionStoreCrud:
    def test_add_and_get(self):
        store = SuppressionStore()
        rule = _rule()
        store.add(rule)
        assert store.get(rule.suppression_id) is not None

    def test_count_increments(self):
        store = SuppressionStore()
        store.add(_rule())
        assert store.count == 1

    def test_remove_returns_true(self):
        store = SuppressionStore()
        rule = _rule()
        store.add(rule)
        assert store.remove(rule.suppression_id) is True

    def test_remove_nonexistent_returns_false(self):
        store = SuppressionStore()
        assert store.remove("nonexistent-id") is False

    def test_all_rules_returns_list(self):
        store = SuppressionStore()
        store.add(_rule(rule_id="A", file_path="f1.py", reason="r"))
        store.add(_rule(rule_id="B", file_path="f2.py", reason="r"))
        assert len(store.all_rules()) == 2

    def test_active_rules_excludes_expired(self):
        store = SuppressionStore()
        store.add(_rule(expires=_future(30)))
        store.add(_rule(rule_id="X", file_path="other.py", reason="r", expires=_past(1)))
        assert len(store.active_rules()) == 1


# ===========================================================================
# SuppressionStore — is_suppressed
# ===========================================================================

class TestIsSupressed:
    def test_exact_path_and_rule_match(self):
        store = SuppressionStore()
        store.add(_rule())
        finding = {"rule_id": "REGEX-001", "file_path": "tests/fixtures/test_data.py"}
        assert store.is_suppressed(finding) is not None

    def test_different_rule_id_not_suppressed(self):
        store = SuppressionStore()
        store.add(_rule())
        finding = {"rule_id": "REGEX-002", "file_path": "tests/fixtures/test_data.py"}
        assert store.is_suppressed(finding) is None

    def test_different_path_not_suppressed(self):
        store = SuppressionStore()
        store.add(_rule())
        finding = {"rule_id": "REGEX-001", "file_path": "src/app.py"}
        assert store.is_suppressed(finding) is None

    def test_wildcard_rule_id_matches_any(self):
        store = SuppressionStore()
        store.add(SuppressionRule(
            rule_id="*",
            file_path="tests/fixtures/test_data.py",
            reason="all rules suppressed here",
        ))
        for rid in ("REGEX-001", "ENTROPY-001", "JWT-001"):
            finding = {"rule_id": rid, "file_path": "tests/fixtures/test_data.py"}
            assert store.is_suppressed(finding) is not None

    def test_glob_path_matches(self):
        store = SuppressionStore()
        store.add(SuppressionRule(
            rule_id="REGEX-001",
            file_path="tests/**",
            reason="all test files",
        ))
        finding = {"rule_id": "REGEX-001", "file_path": "tests/fixtures/some_data.py"}
        assert store.is_suppressed(finding) is not None

    def test_glob_path_no_match_outside(self):
        store = SuppressionStore()
        store.add(SuppressionRule(
            rule_id="REGEX-001",
            file_path="tests/**",
            reason="r",
        ))
        finding = {"rule_id": "REGEX-001", "file_path": "src/production.py"}
        assert store.is_suppressed(finding) is None

    def test_expired_rule_not_applied(self):
        store = SuppressionStore()
        store.add(_rule(expires=_past(1)))
        finding = {"rule_id": "REGEX-001", "file_path": "tests/fixtures/test_data.py"}
        assert store.is_suppressed(finding) is None

    def test_fingerprint_match_required_when_set(self):
        fp = make_fingerprint("secret-value-123")
        store = SuppressionStore()
        store.add(_rule(fingerprint=fp))
        # Same fingerprint matches
        assert store.is_suppressed({
            "rule_id": "REGEX-001",
            "file_path": "tests/fixtures/test_data.py",
            "fingerprint": fp,
        }) is not None
        # Different fingerprint does not match
        assert store.is_suppressed({
            "rule_id": "REGEX-001",
            "file_path": "tests/fixtures/test_data.py",
            "fingerprint": "wrong-fp",
        }) is None


# ===========================================================================
# filter_suppressed
# ===========================================================================

class TestFilterSuppressed:
    def test_splits_correctly(self):
        store = SuppressionStore()
        store.add(_rule())
        findings = [
            {"rule_id": "REGEX-001", "file_path": "tests/fixtures/test_data.py"},
            {"rule_id": "REGEX-001", "file_path": "src/production.py"},
            {"rule_id": "REGEX-002", "file_path": "tests/fixtures/test_data.py"},
        ]
        active, suppressed = store.filter_suppressed(findings)
        assert len(active) == 2
        assert len(suppressed) == 1

    def test_empty_store_all_active(self):
        store = SuppressionStore()
        findings = [{"rule_id": "X", "file_path": "f"}]
        active, suppressed = store.filter_suppressed(findings)
        assert len(active) == 1
        assert len(suppressed) == 0


# ===========================================================================
# expire_stale
# ===========================================================================

class TestExpireStale:
    def test_removes_expired_rules(self):
        store = SuppressionStore()
        store.add(_rule(expires=_past(1)))
        store.add(_rule(rule_id="X", file_path="f2.py", reason="r", expires=_future(30)))
        removed = store.expire_stale()
        assert len(removed) == 1
        assert store.count == 1

    def test_returns_removed_rules(self):
        store = SuppressionStore()
        rule = _rule(expires=_past(1))
        store.add(rule)
        removed = store.expire_stale()
        assert removed[0].suppression_id == rule.suppression_id


# ===========================================================================
# audit_suppressions
# ===========================================================================

class TestAuditSuppressions:
    def test_counts_all_categories(self):
        store = SuppressionStore()
        store.add(_rule(expires=_future(5)))             # active + soon-expiring
        store.add(_rule(rule_id="B", file_path="f2.py", reason="r", expires=_past(1)))   # expired
        store.add(_rule(rule_id="C", file_path="f3.py", reason="r", expires=None))       # permanent
        report = store.audit_suppressions(expiry_warning_days=30)
        assert report.total == 3
        assert report.expired == 1
        assert report.permanent == 1
        assert report.expiring_soon == 1

    def test_summary_contains_counts(self):
        store = SuppressionStore()
        store.add(_rule())
        report = store.audit_suppressions()
        s = report.summary()
        assert "1" in s


# ===========================================================================
# JSON persistence
# ===========================================================================

class TestJsonPersistence:
    def test_save_and_load_round_trip(self):
        store = SuppressionStore()
        store.add(_rule(expires=_future(30)))
        store.add(_rule(rule_id="B", file_path="other.py", reason="r"))

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            store.save_json(path)
            store2 = SuppressionStore.from_json(path)
            assert store2.count == 2
        finally:
            Path(path).unlink(missing_ok=True)

    def test_saved_file_is_valid_json(self):
        store = SuppressionStore()
        store.add(_rule())

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name

        try:
            store.save_json(path)
            data = json.loads(Path(path).read_text())
            assert "rules" in data
            assert "schema_version" in data
        finally:
            Path(path).unlink(missing_ok=True)


# ===========================================================================
# make_fingerprint
# ===========================================================================

class TestMakeFingerprint:
    def test_returns_64_char_hex(self):
        fp = make_fingerprint("evidence-string")
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_deterministic(self):
        assert make_fingerprint("x") == make_fingerprint("x")

    def test_different_inputs_different_output(self):
        assert make_fingerprint("a") != make_fingerprint("b")
