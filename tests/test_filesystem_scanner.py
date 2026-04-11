"""
Tests for scanners/filesystem_scanner.py
==========================================
Validates directory walking, exclusion patterns, binary file skipping,
and integration with the regex and entropy detectors.
"""
import os
import tempfile
from pathlib import Path

import pytest

from scanners.filesystem_scanner import (
    _is_binary_file,
    _matches_any_pattern,
    scan_directory,
)


class TestIsBinaryFile:
    """Tests for the _is_binary_file() helper."""

    def test_png_extension_is_binary(self, tmp_path):
        """Files with .png extension should be classified as binary."""
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n")  # PNG magic bytes
        assert _is_binary_file(f) is True

    def test_python_file_is_not_binary(self, tmp_path):
        """A .py file with text content should not be classified as binary."""
        f = tmp_path / "script.py"
        f.write_text("print('hello')", encoding="utf-8")
        assert _is_binary_file(f) is False

    def test_file_with_null_bytes_is_binary(self, tmp_path):
        """A file containing null bytes should be classified as binary."""
        f = tmp_path / "data.bin"
        f.write_bytes(b"some text\x00more text")
        assert _is_binary_file(f) is True

    def test_yaml_file_is_not_binary(self, tmp_path):
        """A .yaml configuration file should not be classified as binary."""
        f = tmp_path / "config.yaml"
        f.write_text("key: value\n", encoding="utf-8")
        assert _is_binary_file(f) is False


class TestMatchesAnyPattern:
    """Tests for the _matches_any_pattern() helper."""

    def test_matches_directory_name(self, tmp_path):
        """A file under node_modules/ should match the 'node_modules' pattern."""
        file_path = tmp_path / "node_modules" / "lib" / "index.js"
        assert _matches_any_pattern(file_path, tmp_path, ["node_modules"]) is True

    def test_matches_glob_extension_pattern(self, tmp_path):
        """A .min.js file should match the '*.min.js' glob pattern."""
        file_path = tmp_path / "static" / "bundle.min.js"
        assert _matches_any_pattern(file_path, tmp_path, ["*.min.js"]) is True

    def test_does_not_match_unrelated_file(self, tmp_path):
        """A normal Python file should not match any of the default exclusion patterns."""
        file_path = tmp_path / "src" / "main.py"
        patterns = [".git", "node_modules", "*.min.js"]
        assert _matches_any_pattern(file_path, tmp_path, patterns) is False

    def test_matches_dot_git(self, tmp_path):
        """Files under .git/ should match the '.git' pattern."""
        file_path = tmp_path / ".git" / "COMMIT_EDITMSG"
        assert _matches_any_pattern(file_path, tmp_path, [".git"]) is True


class TestScanDirectory:
    """Integration tests for scan_directory()."""

    def test_finds_aws_key_in_python_file(self, tmp_path):
        """scan_directory should detect a synthetic AWS key in a Python file."""
        py_file = tmp_path / "config.py"
        # Synthetic AWS Access Key — non-functional
        py_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

        regex_findings, _ = scan_directory(str(tmp_path), entropy_enabled=False)
        aws_findings = [f for f in regex_findings if f.detector_name == "aws_access_key_id"]
        assert len(aws_findings) == 1
        assert aws_findings[0].file_path.endswith("config.py")

    def test_skips_excluded_directory(self, tmp_path):
        """Files under an excluded directory should not be scanned."""
        excluded_dir = tmp_path / "node_modules" / "lib"
        excluded_dir.mkdir(parents=True)
        secret_file = excluded_dir / "index.js"
        secret_file.write_text('token = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

        regex_findings, _ = scan_directory(
            str(tmp_path),
            entropy_enabled=False,
            ignored_patterns=["node_modules"],
        )
        # No findings should come from the excluded directory
        assert all("node_modules" not in f.file_path for f in regex_findings)

    def test_skips_binary_files(self, tmp_path):
        """Binary files should be skipped without raising an exception."""
        binary_file = tmp_path / "image.png"
        binary_file.write_bytes(b"\x89PNG\r\n\x1a\nFAKECONTENT")

        # This should complete without errors, producing no findings for the PNG
        regex_findings, _ = scan_directory(str(tmp_path), entropy_enabled=False)
        png_findings = [f for f in regex_findings if "image.png" in f.file_path]
        assert png_findings == []

    def test_returns_entropy_findings_when_enabled(self, tmp_path):
        """When entropy is enabled, high-entropy strings should be detected."""
        config_file = tmp_path / "config.yaml"
        # Synthetic high-entropy token in assignment context
        config_file.write_text(
            'api_key: "aB3xY7mK9pQrZ2wE5vN8sD1cF4uH6tL0jI2qWmV"\n',
            encoding="utf-8",
        )

        _, entropy_findings = scan_directory(
            str(tmp_path),
            entropy_enabled=True,
            entropy_threshold=4.0,
        )
        assert len(entropy_findings) >= 1

    def test_returns_empty_for_clean_directory(self, tmp_path):
        """A directory with no secrets should return empty findings lists."""
        clean_file = tmp_path / "hello.py"
        clean_file.write_text("def hello():\n    return 'world'\n", encoding="utf-8")

        regex_findings, entropy_findings = scan_directory(
            str(tmp_path),
            entropy_enabled=True,
            entropy_threshold=4.5,
        )
        assert regex_findings == []
        assert entropy_findings == []

    def test_suppression_file_excludes_file(self, tmp_path):
        """Files listed in the suppression file should not be scanned."""
        # Create a file that would normally produce a finding
        secret_file = tmp_path / "fixture.py"
        secret_file.write_text('key = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

        # Create a suppression file that excludes fixture.py
        suppression_path = tmp_path / ".secret-leak-suppressions.yaml"
        suppression_path.write_text(
            "suppressions:\n"
            '  - file: "fixture.py"\n'
            '    reason: "test fixture"\n',
            encoding="utf-8",
        )

        regex_findings, _ = scan_directory(
            str(tmp_path),
            entropy_enabled=False,
            suppression_file=str(suppression_path),
        )
        # The suppressed file should produce no findings
        fixture_findings = [f for f in regex_findings if "fixture.py" in f.file_path]
        assert fixture_findings == []

    def test_multiple_files_all_scanned(self, tmp_path):
        """Multiple files in a directory should each be scanned."""
        for i in range(3):
            f = tmp_path / f"config_{i}.py"
            f.write_text(f"# config file {i}\nNO_SECRETS = True\n", encoding="utf-8")

        regex_findings, _ = scan_directory(str(tmp_path), entropy_enabled=False)
        # No findings expected, but scan should complete without error
        assert isinstance(regex_findings, list)

    def test_finds_gcp_service_account_json_fields(self, tmp_path):
        """A synthetic GCP service-account JSON file should be detected during a real scan."""
        sa_file = tmp_path / "service-account.json"
        sa_file.write_text(
            '{\n'
            '  "type": "service_account",\n'
            '  "private_key_id": "' + ("a" * 40) + '",\n'
            '  "client_email": "sentinel@demo-project.iam.gserviceaccount.com"\n'
            '}\n',
            encoding="utf-8",
        )

        regex_findings, _ = scan_directory(str(tmp_path), entropy_enabled=False)
        detector_names = {f.detector_name for f in regex_findings}
        assert "gcp_service_account_private_key_id" in detector_names
        assert "gcp_service_account_client_email" in detector_names
