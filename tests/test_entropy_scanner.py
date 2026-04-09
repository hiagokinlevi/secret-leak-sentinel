"""
Tests for scanners.entropy_scanner
====================================
~55 pytest tests covering:
  - _shannon_entropy helper
  - _is_hex_string, _is_base64_string, _is_alnum_string helpers
  - All four check IDs (ENT-001 … ENT-004)
  - scan_text: clean content, keyword co-fire, low-entropy, purely numeric
  - EntropyFinding: masked_value, severity property, to_dict, summary
  - EntropyScanReport: properties, findings_by_check, findings_by_file,
    summary, to_dict
  - EntropyScanner.scan_texts aggregation
  - Deduplication within a single scan_text call
"""

from __future__ import annotations

import sys
import os

# Allow importing the package without an installed distribution
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from scanners.entropy_scanner import (
    EntropyFinding,
    EntropyLevel,
    EntropyScanner,
    EntropyScanReport,
    _is_alnum_string,
    _is_base64_string,
    _is_hex_string,
    _shannon_entropy,
)

# ---------------------------------------------------------------------------
# Shared test fixtures and constants
# ---------------------------------------------------------------------------

# 32-char hex string – all hex characters, clearly high entropy
HIGH_ENTROPY_HEX = "a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5"

# 38-char base64 string – mixed case, digits, valid alphabet, high entropy
HIGH_ENTROPY_B64 = "aGVsbG9Xb3JsZElzQmlnQW5kQmVhdXRpZnVs"

# 32-char mixed-case alphanumeric – no +/= so base64 check won't fire
HIGH_ENTROPY_ALNUM = "aB3xK9mN2pQ7rT5vW8yZ1cD4fG6hJ0lE"

# Short string that should NOT trigger any check
SHORT_STRING = "abc123"

# Purely numeric string that should be skipped
NUMERIC_STRING = "1234567890123456"

# Low-entropy string (all same character repeated)
LOW_ENTROPY_STRING = "aaaaaaaaaaaaaaaa"  # entropy ~0


@pytest.fixture()
def scanner() -> EntropyScanner:
    """Default EntropyScanner with stock thresholds."""
    return EntropyScanner()


# ===========================================================================
# 1. _shannon_entropy
# ===========================================================================

class TestShannonEntropy:
    def test_empty_string_returns_zero(self):
        assert _shannon_entropy("") == 0.0

    def test_single_character_returns_zero(self):
        # Only one distinct symbol → probability 1.0 → log2(1) = 0
        assert _shannon_entropy("a") == pytest.approx(0.0)

    def test_two_equally_probable_chars(self):
        # "ab" repeated → H = 1.0 bit
        assert _shannon_entropy("ab") == pytest.approx(1.0)

    def test_four_equally_probable_chars(self):
        # "abcd" each appear once → H = 2.0 bits
        assert _shannon_entropy("abcd") == pytest.approx(2.0)

    def test_known_high_entropy_hex(self):
        # A well-shuffled 32-char hex string should be significantly above 3.0
        h = _shannon_entropy(HIGH_ENTROPY_HEX)
        assert h > 3.0

    def test_known_high_entropy_b64(self):
        h = _shannon_entropy(HIGH_ENTROPY_B64)
        assert h > 3.5

    def test_known_high_entropy_alnum(self):
        h = _shannon_entropy(HIGH_ENTROPY_ALNUM)
        assert h > 3.5

    def test_low_entropy_repeated_string(self):
        # All same character → entropy 0
        assert _shannon_entropy("aaaaaaaaaa") == pytest.approx(0.0)

    def test_entropy_is_non_negative(self):
        assert _shannon_entropy("hello world") >= 0.0

    def test_entropy_increases_with_diversity(self):
        low = _shannon_entropy("aaaaaaaaaaaaaaaa")
        high = _shannon_entropy(HIGH_ENTROPY_ALNUM)
        assert high > low


# ===========================================================================
# 2. _is_hex_string
# ===========================================================================

class TestIsHexString:
    def test_valid_32_char_hex(self):
        assert _is_hex_string(HIGH_ENTROPY_HEX) is True

    def test_valid_lowercase_hex(self):
        assert _is_hex_string("deadbeefcafebabe0011223344556677") is True

    def test_valid_uppercase_hex(self):
        assert _is_hex_string("DEADBEEFCAFEBABE0011223344556677") is True

    def test_too_short_returns_false(self):
        # Exactly 15 chars – just under the minimum
        assert _is_hex_string("a3f8b2c1d4e5f6a") is False

    def test_minimum_length_16_passes(self):
        assert _is_hex_string("a3f8b2c1d4e5f6a7") is True

    def test_non_hex_char_returns_false(self):
        # 'g' is not a hex digit
        assert _is_hex_string("a3f8b2c1d4e5f6g7") is False

    def test_string_with_space_returns_false(self):
        assert _is_hex_string("a3f8b2c1 d4e5f6a7") is False

    def test_base64_chars_not_hex(self):
        # Contains '+' which is not a hex char
        assert _is_hex_string("X7kM2nP9qR4sT6v+W8") is False


# ===========================================================================
# 3. _is_base64_string
# ===========================================================================

class TestIsBase64String:
    def test_valid_base64_string(self):
        assert _is_base64_string(HIGH_ENTROPY_B64) is True

    def test_string_with_plus_and_slash(self):
        # 34 chars, valid base64 alphabet, mixed case
        s = "X7kM2nP9qR4sT6v+W8yZ1cA3fB5hD0jE2"
        assert _is_base64_string(s) is True

    def test_too_short_returns_false(self):
        assert _is_base64_string("aGVsbG9Xb3Jsc") is False  # < 20 chars

    def test_minimum_length_20_passes(self):
        # Exactly 20 chars, mixed case, valid alphabet
        assert _is_base64_string("aGVsbG9Xb3JsZElzQmlg") is True

    def test_no_uppercase_returns_false(self):
        # All lowercase + digits – fails mixed-case requirement
        assert _is_base64_string("aaaaabbbbccccddddeeee") is False

    def test_no_lowercase_returns_false(self):
        # All uppercase + digits
        assert _is_base64_string("AAAABBBBCCCCDDDDEEEE1") is False

    def test_invalid_char_returns_false(self):
        # '#' is not in base64 alphabet
        assert _is_base64_string("aGVsbG9Xb3JsZElzQmlg#") is False

    def test_all_hex_chars_no_case_mix_fails(self):
        # Pure lowercase hex won't satisfy has_upper
        assert _is_base64_string("a3f8b2c1d4e5f6a7b8c9d0") is False


# ===========================================================================
# 4. _is_alnum_string
# ===========================================================================

class TestIsAlnumString:
    def test_valid_alnum_string(self):
        assert _is_alnum_string(HIGH_ENTROPY_ALNUM) is True

    def test_too_short_returns_false(self):
        assert _is_alnum_string("aB3xK9mN") is False  # < 16 chars

    def test_minimum_length_16_passes(self):
        assert _is_alnum_string("aB3xK9mN2pQ7rT5v") is True

    def test_no_digit_returns_false(self):
        # No digits in the string
        assert _is_alnum_string("aAbBcCdDeEfFgGhH") is False

    def test_no_uppercase_returns_false(self):
        assert _is_alnum_string("ab3xk9mn2pq7rt5v") is False

    def test_no_lowercase_returns_false(self):
        assert _is_alnum_string("AB3XK9MN2PQ7RT5V") is False

    def test_special_char_returns_false(self):
        # '+' is not alnum
        assert _is_alnum_string("aB3xK9mN2pQ7+T5v") is False

    def test_all_digits_returns_false(self):
        # Purely numeric – isdigit() short-circuit and digit-only check fails
        assert _is_alnum_string("1234567890123456") is False


# ===========================================================================
# 5. ENT-001: high-entropy hex strings
# ===========================================================================

class TestENT001:
    def test_fires_on_high_entropy_hex(self, scanner):
        line = f'hash = "{HIGH_ENTROPY_HEX}"'
        findings = scanner.scan_text(line)
        ids = [f.check_id for f in findings]
        assert "ENT-001" in ids

    def test_does_not_fire_on_short_hex(self, scanner):
        # 15-char hex – below min_length
        findings = scanner.scan_text('x = "a3f8b2c1d4e5f6a"')
        assert not any(f.check_id == "ENT-001" for f in findings)

    def test_does_not_fire_on_low_entropy_hex(self, scanner):
        # 16 zeros – valid hex, but entropy ≈ 0
        findings = scanner.scan_text('x = "0000000000000000"')
        assert not any(f.check_id == "ENT-001" for f in findings)

    def test_check_id_string_correct(self, scanner):
        findings = scanner.scan_text(HIGH_ENTROPY_HEX)
        assert any(f.check_id == "ENT-001" for f in findings)


# ===========================================================================
# 6. ENT-002: high-entropy base64 strings
# ===========================================================================

class TestENT002:
    def test_fires_on_high_entropy_base64(self, scanner):
        line = f'secret = "{HIGH_ENTROPY_B64}"'
        findings = scanner.scan_text(line)
        ids = [f.check_id for f in findings]
        assert "ENT-002" in ids

    def test_does_not_fire_on_short_base64(self, scanner):
        findings = scanner.scan_text('x = "aGVsbG9X"')
        assert not any(f.check_id == "ENT-002" for f in findings)

    def test_does_not_fire_on_all_lowercase(self, scanner):
        # 25 chars, all lowercase – fails _is_base64_string has_upper check
        findings = scanner.scan_text('x = "aaaaabbbbccccddddeeeefffff"')
        assert not any(f.check_id == "ENT-002" for f in findings)


# ===========================================================================
# 7. ENT-003: high-entropy alphanumeric strings
# ===========================================================================

class TestENT003:
    def test_fires_on_high_entropy_alnum(self, scanner):
        line = f'api_key = "{HIGH_ENTROPY_ALNUM}"'
        findings = scanner.scan_text(line)
        ids = [f.check_id for f in findings]
        assert "ENT-003" in ids

    def test_does_not_fire_on_short_alnum(self, scanner):
        findings = scanner.scan_text('x = "aB3xK9mN"')
        assert not any(f.check_id == "ENT-003" for f in findings)

    def test_does_not_fire_on_no_uppercase(self, scanner):
        findings = scanner.scan_text('x = "ab3xk9mn2pq7rt5v"')
        assert not any(f.check_id == "ENT-003" for f in findings)

    def test_does_not_fire_on_low_entropy_alnum(self, scanner):
        # Repeat pattern – low entropy even though it's alnum
        findings = scanner.scan_text('x = "aB1aB1aB1aB1aB1aB1"')
        assert not any(f.check_id == "ENT-003" for f in findings)


# ===========================================================================
# 8. ENT-004: high-entropy string adjacent to secret keyword
# ===========================================================================

class TestENT004:
    def test_fires_when_keyword_and_high_entropy_same_line(self, scanner):
        # "api_key" contains keyword "key"
        line = f'api_key = "{HIGH_ENTROPY_ALNUM}"'
        findings = scanner.scan_text(line)
        assert any(f.check_id == "ENT-004" for f in findings)

    def test_keyword_populated_in_finding(self, scanner):
        line = f'password = "{HIGH_ENTROPY_ALNUM}"'
        findings = scanner.scan_text(line)
        ent4 = [f for f in findings if f.check_id == "ENT-004"]
        assert ent4, "Expected at least one ENT-004 finding"
        assert ent4[0].keyword != ""

    def test_does_not_fire_when_no_keyword_on_line(self, scanner):
        # No secret keyword; plain variable name
        line = f'config_value = "{HIGH_ENTROPY_ALNUM}"'
        findings = scanner.scan_text(line)
        assert not any(f.check_id == "ENT-004" for f in findings)

    def test_does_not_fire_on_low_entropy_even_with_keyword(self, scanner):
        # "password" keyword but the value has near-zero entropy
        line = 'password = "hunter2"'
        findings = scanner.scan_text(line)
        assert not any(f.check_id == "ENT-004" for f in findings)

    def test_ent004_cofires_with_ent003(self, scanner):
        # Same string should produce BOTH ENT-003 and ENT-004
        line = f'secret_key = "{HIGH_ENTROPY_ALNUM}"'
        findings = scanner.scan_text(line)
        ids = {f.check_id for f in findings}
        assert "ENT-003" in ids
        assert "ENT-004" in ids

    def test_keyword_case_insensitive(self, scanner):
        # "TOKEN" in uppercase should still match keyword "token"
        line = f'TOKEN = "{HIGH_ENTROPY_ALNUM}"'
        findings = scanner.scan_text(line)
        assert any(f.check_id == "ENT-004" for f in findings)

    def test_various_keywords_trigger_ent004(self, scanner):
        keywords_and_lines = [
            f'db_secret = "{HIGH_ENTROPY_ALNUM}"',
            f'auth_token = "{HIGH_ENTROPY_ALNUM}"',
            f'private_key = "{HIGH_ENTROPY_ALNUM}"',
            f'bearer_value = "{HIGH_ENTROPY_ALNUM}"',
        ]
        for line in keywords_and_lines:
            findings = scanner.scan_text(line)
            assert any(f.check_id == "ENT-004" for f in findings), (
                f"ENT-004 should fire for line: {line}"
            )


# ===========================================================================
# 9. Clean content / negative cases
# ===========================================================================

class TestCleanContent:
    def test_empty_content_no_findings(self, scanner):
        assert scanner.scan_text("") == []

    def test_clean_config_no_findings(self, scanner):
        content = """
        [database]
        host = localhost
        port = 5432
        name = myapp
        """
        assert scanner.scan_text(content) == []

    def test_purely_numeric_string_not_flagged(self, scanner):
        line = f"timestamp = {NUMERIC_STRING}"
        findings = scanner.scan_text(line)
        assert findings == []

    def test_short_strings_not_flagged(self, scanner):
        findings = scanner.scan_text('x = "abc123"')
        assert findings == []

    def test_low_entropy_long_string_not_flagged(self, scanner):
        # Very long but all same character – entropy = 0
        findings = scanner.scan_text('x = "' + "a" * 64 + '"')
        assert findings == []

    def test_normal_english_sentence_no_findings(self, scanner):
        findings = scanner.scan_text(
            "The quick brown fox jumps over the lazy dog."
        )
        assert findings == []


# ===========================================================================
# 10. EntropyFinding: masked_value and severity
# ===========================================================================

class TestEntropyFinding:
    def _make_finding(self, entropy: float, value: str = "aB3xK9mN2pQ7rT5v") -> EntropyFinding:
        return EntropyFinding(
            check_id="ENT-003",
            entropy=entropy,
            value=value,
            masked_value=value[:4] + "****" if len(value) > 4 else "****",
        )

    def test_masked_value_format_long_value(self):
        f = self._make_finding(4.5, value="aB3xK9mN2pQ7rT5vW8")
        assert f.masked_value == "aB3x****"

    def test_masked_value_format_exactly_4_chars(self):
        f = EntropyFinding(
            check_id="ENT-003",
            entropy=3.5,
            value="abcd",
            masked_value="****",
        )
        assert f.masked_value == "****"

    def test_masked_value_short_value_is_stars(self):
        f = EntropyFinding(
            check_id="ENT-003",
            entropy=3.5,
            value="abc",
            masked_value="****",
        )
        assert f.masked_value == "****"

    def test_severity_critical(self):
        f = self._make_finding(entropy=5.1)
        assert f.severity == "CRITICAL"

    def test_severity_high(self):
        f = self._make_finding(entropy=4.5)
        assert f.severity == "HIGH"

    def test_severity_medium(self):
        f = self._make_finding(entropy=3.7)
        assert f.severity == "MEDIUM"

    def test_severity_low(self):
        f = self._make_finding(entropy=3.1)
        assert f.severity == "LOW"

    def test_severity_at_critical_boundary(self):
        f = self._make_finding(entropy=5.0)
        assert f.severity == "CRITICAL"

    def test_severity_just_below_critical(self):
        f = self._make_finding(entropy=4.99)
        assert f.severity == "HIGH"

    def test_to_dict_contains_severity(self):
        f = self._make_finding(entropy=4.5)
        d = f.to_dict()
        assert "severity" in d
        assert d["severity"] == "HIGH"

    def test_to_dict_contains_all_expected_keys(self):
        f = self._make_finding(entropy=4.5)
        d = f.to_dict()
        expected_keys = {
            "check_id", "severity", "entropy", "value", "masked_value",
            "source_file", "line_number", "context", "keyword",
        }
        assert expected_keys.issubset(d.keys())

    def test_to_dict_entropy_rounded(self):
        f = self._make_finding(entropy=3.123456789)
        d = f.to_dict()
        # Should be rounded to 4 decimal places
        assert d["entropy"] == round(3.123456789, 4)

    def test_summary_contains_check_id(self):
        f = self._make_finding(entropy=4.5)
        assert "ENT-003" in f.summary()

    def test_summary_contains_severity(self):
        f = self._make_finding(entropy=4.5)
        assert "HIGH" in f.summary()

    def test_summary_contains_masked_value(self):
        f = self._make_finding(entropy=4.5, value="aB3xK9mN2pQ7rT5vW8")
        assert "aB3x****" in f.summary()


# ===========================================================================
# 11. EntropyScanReport
# ===========================================================================

class TestEntropyScanReport:
    def _sample_findings(self) -> list:
        def _f(check_id, entropy, file="a.py", lineno=1):
            return EntropyFinding(
                check_id=check_id,
                entropy=entropy,
                value="aB3xK9mN2pQ7rT5v",
                masked_value="aB3x****",
                source_file=file,
                line_number=lineno,
            )

        return [
            _f("ENT-001", 5.2, "a.py", 1),
            _f("ENT-001", 5.0, "a.py", 2),
            _f("ENT-002", 4.5, "b.py", 3),
            _f("ENT-003", 3.7, "b.py", 4),
            _f("ENT-004", 3.1, "c.py", 5),
        ]

    def test_total_findings_property(self):
        report = EntropyScanReport(findings=self._sample_findings())
        assert report.total_findings == 5

    def test_critical_findings_property(self):
        report = EntropyScanReport(findings=self._sample_findings())
        # entropy=5.2 and 5.0 both qualify as CRITICAL
        assert report.critical_findings == 2

    def test_high_findings_property(self):
        report = EntropyScanReport(findings=self._sample_findings())
        # entropy=4.5 qualifies as HIGH
        assert report.high_findings == 1

    def test_findings_by_check(self):
        report = EntropyScanReport(findings=self._sample_findings())
        by_check = report.findings_by_check()
        assert "ENT-001" in by_check
        assert len(by_check["ENT-001"]) == 2
        assert len(by_check.get("ENT-002", [])) == 1

    def test_findings_by_file(self):
        report = EntropyScanReport(findings=self._sample_findings())
        by_file = report.findings_by_file()
        assert "a.py" in by_file
        assert len(by_file["a.py"]) == 2
        assert len(by_file.get("b.py", [])) == 2
        assert len(by_file.get("c.py", [])) == 1

    def test_summary_contains_counts(self):
        report = EntropyScanReport(findings=self._sample_findings(), files_scanned=3)
        s = report.summary()
        assert "5" in s  # total findings
        assert "3" in s  # files_scanned

    def test_to_dict_structure(self):
        report = EntropyScanReport(findings=self._sample_findings(), files_scanned=3, strings_analyzed=20)
        d = report.to_dict()
        assert d["total_findings"] == 5
        assert d["files_scanned"] == 3
        assert d["strings_analyzed"] == 20
        assert len(d["findings"]) == 5

    def test_to_dict_findings_include_severity(self):
        report = EntropyScanReport(findings=self._sample_findings())
        d = report.to_dict()
        for f_dict in d["findings"]:
            assert "severity" in f_dict

    def test_empty_report(self):
        report = EntropyScanReport()
        assert report.total_findings == 0
        assert report.critical_findings == 0
        assert report.high_findings == 0
        assert report.findings_by_check() == {}
        assert report.findings_by_file() == {}


# ===========================================================================
# 12. scan_texts aggregation
# ===========================================================================

class TestScanTexts:
    def test_aggregates_findings_across_items(self, scanner):
        items = [
            {"content": f'api_key = "{HIGH_ENTROPY_ALNUM}"', "source_file": "a.py"},
            {"content": f'secret = "{HIGH_ENTROPY_B64}"', "source_file": "b.py"},
        ]
        report = scanner.scan_texts(items)
        assert report.total_findings > 0
        assert report.files_scanned == 2

    def test_files_scanned_matches_item_count(self, scanner):
        items = [
            {"content": "x = 1", "source_file": "a.py"},
            {"content": "y = 2", "source_file": "b.py"},
            {"content": "z = 3", "source_file": "c.py"},
        ]
        report = scanner.scan_texts(items)
        assert report.files_scanned == 3

    def test_source_file_preserved_in_findings(self, scanner):
        items = [
            {"content": f'key = "{HIGH_ENTROPY_ALNUM}"', "source_file": "secrets.env"},
        ]
        report = scanner.scan_texts(items)
        for f in report.findings:
            assert f.source_file == "secrets.env"

    def test_empty_items_list_returns_empty_report(self, scanner):
        report = scanner.scan_texts([])
        assert report.total_findings == 0
        assert report.files_scanned == 0

    def test_strings_analyzed_is_positive_for_non_empty_content(self, scanner):
        items = [{"content": f'api_key = "{HIGH_ENTROPY_ALNUM}"'}]
        report = scanner.scan_texts(items)
        assert report.strings_analyzed > 0

    def test_missing_source_file_key_defaults_to_empty(self, scanner):
        items = [{"content": f'key = "{HIGH_ENTROPY_ALNUM}"'}]
        report = scanner.scan_texts(items)
        for f in report.findings:
            assert f.source_file == ""


# ===========================================================================
# 13. Deduplication
# ===========================================================================

class TestDeduplication:
    def test_duplicate_occurrence_on_same_line_not_double_counted(self, scanner):
        # Same value appearing twice on same line should still deduplicate by
        # (value, check_id, line_number)
        val = HIGH_ENTROPY_ALNUM
        line = f'{val} {val}'
        findings = scanner.scan_text(line)
        ent3_findings = [f for f in findings if f.check_id == "ENT-003"]
        # Should only appear once for ENT-003
        assert len(ent3_findings) == 1

    def test_same_value_different_lines_not_deduplicated(self, scanner):
        # Same high-entropy value on two different lines → two findings
        val = HIGH_ENTROPY_ALNUM
        content = f"x = {val}\ny = {val}"
        findings = scanner.scan_text(content)
        ent3_findings = [f for f in findings if f.check_id == "ENT-003"]
        assert len(ent3_findings) == 2

    def test_different_values_both_reported(self, scanner):
        content = f"x = {HIGH_ENTROPY_ALNUM}\ny = {HIGH_ENTROPY_HEX}"
        findings = scanner.scan_text(content)
        values = {f.value for f in findings}
        assert HIGH_ENTROPY_ALNUM in values
        assert HIGH_ENTROPY_HEX in values


# ===========================================================================
# 14. EntropyLevel enum
# ===========================================================================

class TestEntropyLevel:
    def test_critical_threshold(self):
        assert EntropyLevel.CRITICAL.value == 5.0

    def test_high_threshold(self):
        assert EntropyLevel.HIGH.value == 4.0

    def test_medium_threshold(self):
        assert EntropyLevel.MEDIUM.value == 3.5

    def test_low_threshold(self):
        assert EntropyLevel.LOW.value == 3.0
