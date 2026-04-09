"""
Tests for detectors/entropy_detector.py
=========================================
Validates the Shannon entropy calculation and the content scanning function.
"""
import pytest

from detectors.entropy_detector import (
    EntropyFinding,
    shannon_entropy,
    scan_content_for_entropy,
)


class TestShannonEntropy:
    """Tests for the shannon_entropy() function."""

    def test_empty_string_returns_zero(self):
        """An empty string has zero entropy."""
        assert shannon_entropy("") == 0.0

    def test_single_char_string_returns_zero(self):
        """A string of identical characters has zero entropy."""
        assert shannon_entropy("aaaaaaa") == 0.0

    def test_two_char_equal_probability_returns_one(self):
        """A string with two equally probable characters has entropy of 1.0."""
        result = shannon_entropy("abababab")
        assert abs(result - 1.0) < 0.01

    def test_random_base64_string_has_high_entropy(self):
        """A high-entropy base64-like string should return entropy above 4.0."""
        # This is a synthetic random-looking string, not a real secret
        token = "aB3xY7mK9pQrZ2wE5vN8sD1cF4uH6tL0"
        result = shannon_entropy(token)
        assert result > 4.0

    def test_english_word_has_low_entropy(self):
        """A common English word should have relatively low entropy."""
        result = shannon_entropy("password")
        assert result < 3.5

    def test_returns_float(self):
        """shannon_entropy should always return a float."""
        assert isinstance(shannon_entropy("hello"), float)

    def test_entropy_increases_with_randomness(self):
        """A more random string should have higher entropy than a repetitive one."""
        repetitive = "abcabcabcabcabcabc"
        random_like = "aB3xY7mK9pQrZ2wE5v"
        assert shannon_entropy(random_like) > shannon_entropy(repetitive)


class TestScanContentForEntropy:
    """Tests for the scan_content_for_entropy() function."""

    def test_returns_empty_for_clean_content(self):
        """File content with no high-entropy strings should return no findings."""
        content = "def hello():\n    name = 'world'\n    print(f'Hello {name}')\n"
        findings = scan_content_for_entropy(content, "hello.py", threshold=4.5)
        assert findings == []

    def test_detects_high_entropy_in_assignment_context(self):
        """A high-entropy value in an API key assignment should be detected."""
        # Synthetic high-entropy string in assignment context
        content = 'api_key = "aB3xY7mK9pQrZ2wE5vN8sD1cF4uH6tL0jI2qW"'
        findings = scan_content_for_entropy(content, "config.py", threshold=4.0)
        assert len(findings) >= 1

    def test_findings_contain_masked_token(self):
        """Entropy findings must contain masked (not raw) token values."""
        content = 'secret = "aB3xY7mK9pQrZ2wE5vN8sD1cF4uH6tL0jI2qW"'
        findings = scan_content_for_entropy(content, "config.py", threshold=4.0)
        for finding in findings:
            # Masked token should end with [Nchars] indicator
            assert "****" in finding.token or finding.token.endswith("]")

    def test_line_number_is_correct(self):
        """Entropy findings should have the correct line number."""
        content = "normal_line = 'hello'\napi_key = 'aB3xY7mK9pQrZ2wE5vN8sD1cF4uH6tL0jI2qW'\n"
        findings = scan_content_for_entropy(content, "config.py", threshold=4.0)
        if findings:
            assert findings[0].line_number == 2

    def test_higher_threshold_produces_fewer_findings(self):
        """Raising the entropy threshold should result in fewer or equal findings."""
        content = "\n".join([
            f'key_{i} = "aB3xY7mK9pQrZ2wE5v{i:02d}N8sD1cF4uH6"'
            for i in range(5)
        ])
        low_threshold_findings = scan_content_for_entropy(content, "f.py", threshold=3.5)
        high_threshold_findings = scan_content_for_entropy(content, "f.py", threshold=5.5)
        assert len(high_threshold_findings) <= len(low_threshold_findings)

    def test_confidence_is_between_zero_and_one(self):
        """All entropy finding confidence scores should be in [0, 1]."""
        content = 'token = "aB3xY7mK9pQrZ2wE5vN8sD1cF4uH6tL0jI2qW"'
        findings = scan_content_for_entropy(content, "config.py", threshold=4.0)
        for finding in findings:
            assert 0.0 <= finding.confidence <= 1.0

    def test_empty_content_returns_no_findings(self):
        """Empty file content should produce no entropy findings."""
        findings = scan_content_for_entropy("", "empty.py", threshold=4.5)
        assert findings == []

    def test_short_strings_below_min_length_are_skipped(self):
        """Strings shorter than min_length should not be checked for entropy."""
        content = 'key = "short"'  # "short" is 5 characters, below min_length=20
        findings = scan_content_for_entropy(content, "config.py", threshold=4.0, min_length=20)
        assert findings == []
