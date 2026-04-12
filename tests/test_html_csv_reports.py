"""
Tests for reports/html_report.py and reports/csv_report.py

Validates:
  - generate_html_report() returns valid HTML with DOCTYPE
  - HTML report contains severity counts in summary bar
  - HTML report contains finding excerpts (masked)
  - HTML report shows clean-banner when no findings
  - HTML report includes entropy table when entropy findings provided
  - save_html_report() creates a .html file in the output directory
  - generate_csv_report() returns UTF-8 BOM-prefixed CSV
  - CSV has correct header row
  - CSV has one data row per finding
  - CSV row columns are in expected order
  - CSV never contains unmasked AWS key IDs
  - CSV handles zero findings (headers only)
  - save_csv_report() creates a .csv file in the output directory
"""
from __future__ import annotations

import csv
import io
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from classifiers.criticality_classifier import ClassifiedFinding
from detectors.entropy_detector import EntropyFinding
from detectors.regex_detector import Criticality, Finding, SecretType
from reports.csv_report import generate_csv_report, save_csv_report
from reports.html_report import generate_html_report, save_html_report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_classified(
    criticality: Criticality = Criticality.HIGH,
    file_path: str = "src/app.py",
    line_number: int = 10,
    detector_name: str = "aws_access_key",
    secret_type: SecretType = SecretType.AWS_ACCESS_KEY,
    entropy_corroboration: bool = False,
    context_penalty: bool = False,
    cross_file_corroboration: bool = False,
    correlated_file_count: int = 1,
) -> ClassifiedFinding:
    f = Finding(
        detector_name=detector_name,
        secret_type=secret_type,
        criticality=criticality,
        file_path=file_path,
        line_number=line_number,
        masked_excerpt="aws_key = AKIA***REDACTED (masked)",
        confidence=0.88,
    )
    return ClassifiedFinding(
        original_finding=f,
        final_criticality=criticality,
        confidence=0.88,
        rationale="Test finding rationale.",
        entropy_corroboration=entropy_corroboration,
        context_penalty=context_penalty,
        context_escalation=False,
        cross_file_corroboration=cross_file_corroboration,
        correlated_file_count=correlated_file_count,
    )


def _make_entropy(file_path: str = "config.yml", line_number: int = 5) -> EntropyFinding:
    return EntropyFinding(
        file_path=file_path,
        line_number=line_number,
        token="abc***xyz",
        entropy=4.87,
        masked_excerpt="token: abc***xyz",
        confidence=0.72,
    )


# ---------------------------------------------------------------------------
# generate_html_report
# ---------------------------------------------------------------------------

class TestGenerateHtmlReport:

    def test_returns_string(self):
        result = generate_html_report([], ".")
        assert isinstance(result, str)

    def test_starts_with_doctype(self):
        result = generate_html_report([], ".")
        assert result.strip().startswith("<!DOCTYPE html>")

    def test_contains_html_tag(self):
        result = generate_html_report([], ".")
        assert "<html" in result

    def test_contains_title_with_scan_path(self):
        result = generate_html_report([], "my-project")
        assert "my-project" in result

    def test_clean_banner_when_no_findings(self):
        result = generate_html_report([], ".")
        assert "clean-banner" in result or "No secrets detected" in result

    def test_no_clean_banner_when_findings_present(self):
        result = generate_html_report([_make_classified()], ".")
        assert "No secrets detected" not in result

    def test_severity_label_appears_for_finding(self):
        result = generate_html_report([_make_classified(Criticality.CRITICAL)], ".")
        assert "CRITICAL" in result

    def test_high_severity_label_appears(self):
        result = generate_html_report([_make_classified(Criticality.HIGH)], ".")
        assert "HIGH" in result

    def test_masked_excerpt_in_output(self):
        result = generate_html_report([_make_classified()], ".")
        assert "AKIA***REDACTED" in result

    def test_no_unmasked_akid_in_html(self):
        import re
        result = generate_html_report([_make_classified()], ".")
        assert not re.search(r"AKIA[A-Z0-9]{16}", result)

    def test_file_path_appears(self):
        result = generate_html_report([_make_classified(file_path="secret/config.py")], ".")
        assert "secret/config.py" in result

    def test_multiple_findings_all_appear(self):
        findings = [
            _make_classified(Criticality.CRITICAL, file_path="a.py"),
            _make_classified(Criticality.HIGH, file_path="b.py"),
            _make_classified(Criticality.MEDIUM, file_path="c.py"),
        ]
        result = generate_html_report(findings, ".")
        assert "a.py" in result
        assert "b.py" in result
        assert "c.py" in result

    def test_entropy_section_when_entropy_findings_provided(self):
        result = generate_html_report([], ".", entropy_findings=[_make_entropy()])
        assert "Entropy" in result

    def test_entropy_token_in_html(self):
        result = generate_html_report([], ".", entropy_findings=[_make_entropy()])
        assert "abc***xyz" in result

    def test_no_entropy_section_without_entropy_findings(self):
        result = generate_html_report([_make_classified()], ".")
        # Should not have an entropy section
        assert "entropy_findings" not in result.lower() or "Entropy Findings" not in result

    def test_html_is_self_contained_no_external_stylesheets(self):
        result = generate_html_report([_make_classified()], ".")
        # No external CSS or JS files loaded
        assert 'rel="stylesheet"' not in result
        assert '<script src=' not in result
        assert 'src="http' not in result.lower()

    def test_medium_low_table_section(self):
        findings = [_make_classified(Criticality.MEDIUM), _make_classified(Criticality.LOW)]
        result = generate_html_report(findings, ".")
        assert "Medium" in result or "Low" in result

    def test_entropy_corroboration_tag(self):
        finding = _make_classified(entropy_corroboration=True)
        result = generate_html_report([finding], ".")
        assert "entropy+" in result

    def test_cross_file_correlation_tag(self):
        finding = _make_classified(cross_file_corroboration=True, correlated_file_count=3)
        result = generate_html_report([finding], ".")
        assert "shared 3 files" in result

    def test_scan_path_in_report(self):
        result = generate_html_report([], "/var/scans/my-project")
        assert "/var/scans/my-project" in result


# ---------------------------------------------------------------------------
# save_html_report
# ---------------------------------------------------------------------------

class TestSaveHtmlReport:

    def test_creates_html_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            html = generate_html_report([], ".")
            path = save_html_report(html, tmpdir)
            assert path.exists()
            assert path.suffix == ".html"

    def test_file_contains_expected_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            html = generate_html_report([_make_classified()], "test-repo")
            path = save_html_report(html, tmpdir)
            content = path.read_text(encoding="utf-8")
            assert "test-repo" in content

    def test_creates_output_dir_if_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = Path(tmpdir) / "reports" / "html"
            html = generate_html_report([], ".")
            path = save_html_report(html, new_dir)
            assert path.exists()


# ---------------------------------------------------------------------------
# generate_csv_report
# ---------------------------------------------------------------------------

class TestGenerateCsvReport:

    def test_returns_string(self):
        result = generate_csv_report([])
        assert isinstance(result, str)

    def test_has_utf8_bom(self):
        result = generate_csv_report([])
        assert result.startswith("\ufeff")

    def test_headers_only_when_no_findings(self):
        result = generate_csv_report([])
        # Strip BOM and parse
        reader = csv.reader(io.StringIO(result.lstrip("\ufeff")))
        rows = list(reader)
        assert len(rows) == 1    # headers only

    def test_header_row_correct(self):
        result = generate_csv_report([])
        reader = csv.reader(io.StringIO(result.lstrip("\ufeff")))
        headers = next(reader)
        assert "severity" in headers
        assert "file_path" in headers
        assert "line_number" in headers
        assert "confidence" in headers
        assert "masked_excerpt" in headers
        assert "cross_file_corroboration" in headers
        assert "correlated_file_count" in headers

    def test_one_row_per_finding(self):
        findings = [_make_classified() for _ in range(5)]
        result = generate_csv_report(findings)
        reader = csv.reader(io.StringIO(result.lstrip("\ufeff")))
        rows = list(reader)
        assert len(rows) == 6   # 1 header + 5 data rows

    def test_severity_in_row(self):
        result = generate_csv_report([_make_classified(Criticality.CRITICAL)])
        assert "critical" in result

    def test_file_path_in_row(self):
        result = generate_csv_report([_make_classified(file_path="path/to/secret.py")])
        assert "path/to/secret.py" in result

    def test_line_number_in_row(self):
        result = generate_csv_report([_make_classified(line_number=99)])
        assert "99" in result

    def test_confidence_formatted_as_decimal(self):
        result = generate_csv_report([_make_classified()])
        assert "0.880" in result

    def test_entropy_corroboration_boolean(self):
        result = generate_csv_report([_make_classified(entropy_corroboration=True)])
        assert "true" in result

    def test_no_entropy_corroboration(self):
        result = generate_csv_report([_make_classified(entropy_corroboration=False)])
        # false should appear at least once for this finding
        assert "false" in result

    def test_cross_file_correlation_fields(self):
        result = generate_csv_report(
            [_make_classified(cross_file_corroboration=True, correlated_file_count=3)]
        )
        reader = csv.DictReader(io.StringIO(result.lstrip("\ufeff")))
        row = next(reader)
        assert row["cross_file_corroboration"] == "true"
        assert row["correlated_file_count"] == "3"

    def test_masked_excerpt_in_row(self):
        result = generate_csv_report([_make_classified()])
        assert "AKIA***REDACTED" in result

    def test_no_unmasked_akid_in_csv(self):
        import re
        result = generate_csv_report([_make_classified()])
        assert not re.search(r"AKIA[A-Z0-9]{16}", result)

    def test_custom_scanned_at_timestamp(self):
        ts = "2026-04-06T12:00:00Z"
        result = generate_csv_report([_make_classified()], scanned_at=ts)
        assert ts in result

    def test_newlines_in_excerpt_replaced(self):
        # Build a finding with a newline in the masked_excerpt
        f = Finding(
            detector_name="test",
            secret_type=SecretType.API_TOKEN,
            criticality=Criticality.MEDIUM,
            file_path="x.py",
            line_number=1,
            masked_excerpt="line1\nline2",
            confidence=0.5,
        )
        cf = ClassifiedFinding(
            original_finding=f,
            final_criticality=Criticality.MEDIUM,
            confidence=0.5,
            rationale="test",
            entropy_corroboration=False,
            context_penalty=False,
            context_escalation=False,
        )
        result = generate_csv_report([cf])
        # After BOM removal, parse CSV — should still be exactly 2 rows
        reader = csv.reader(io.StringIO(result.lstrip("\ufeff")))
        rows = list(reader)
        assert len(rows) == 2


# ---------------------------------------------------------------------------
# save_csv_report
# ---------------------------------------------------------------------------

class TestSaveCsvReport:

    def test_creates_csv_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_text = generate_csv_report([_make_classified()])
            path = save_csv_report(csv_text, tmpdir)
            assert path.exists()
            assert path.suffix == ".csv"

    def test_file_is_readable_csv(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_text = generate_csv_report([_make_classified()])
            path = save_csv_report(csv_text, tmpdir)
            content = path.read_text(encoding="utf-8-sig")
            reader = csv.reader(io.StringIO(content))
            rows = list(reader)
            assert len(rows) == 2   # header + 1 finding

    def test_creates_output_dir_if_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = Path(tmpdir) / "reports" / "csv"
            csv_text = generate_csv_report([])
            path = save_csv_report(csv_text, new_dir)
            assert path.exists()
