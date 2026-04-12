"""
CSV Scan Report Export
=======================
Exports classified secret scan findings as a CSV file for ingestion into
spreadsheets, SIEMs, ticketing systems, and data pipelines.

Each row represents one finding. Columns are ordered for readability and
SIEM compatibility:
  severity, detector_name, secret_type, file_path, line_number,
  confidence, entropy_corroboration, cross_file_corroboration,
  correlated_file_count, context_penalty, context_escalation,
  masked_excerpt, rationale, scanned_at

Design notes:
  - Secret values are never included — only masked_excerpt from the finding.
  - The output is UTF-8 BOM-prefixed so Excel opens it correctly on Windows.
  - Newlines within masked_excerpt are replaced with a space to keep each
    finding on one CSV row.

Usage:
    from reports.csv_report import generate_csv_report, save_csv_report
    from classifiers.criticality_classifier import ClassifiedFinding

    csv_text = generate_csv_report(classified_findings)
    path = save_csv_report(csv_text, output_dir="./scan-results")
"""
from __future__ import annotations

import csv
import io
from datetime import datetime
from pathlib import Path

from classifiers.criticality_classifier import ClassifiedFinding


# CSV column headers — stable order for downstream tooling
_HEADERS: list[str] = [
    "severity",
    "detector_name",
    "secret_type",
    "file_path",
    "line_number",
    "confidence",
    "entropy_corroboration",
    "cross_file_corroboration",
    "correlated_file_count",
    "context_penalty",
    "context_escalation",
    "masked_excerpt",
    "rationale",
    "scanned_at",
]


def _finding_to_row(cf: ClassifiedFinding, scanned_at: str) -> list[str]:
    """Convert a ClassifiedFinding to an ordered CSV row."""
    f = cf.original_finding
    # Replace newlines in excerpt to keep the finding on one row
    safe_excerpt = cf.original_finding.masked_excerpt.replace("\n", " ").replace("\r", "")
    return [
        cf.final_criticality.value,
        f.detector_name,
        f.secret_type.value,
        f.file_path,
        str(f.line_number),
        f"{cf.confidence:.3f}",
        "true" if cf.entropy_corroboration else "false",
        "true" if cf.cross_file_corroboration else "false",
        str(cf.correlated_file_count),
        "true" if cf.context_penalty       else "false",
        "true" if cf.context_escalation    else "false",
        safe_excerpt,
        cf.rationale,
        scanned_at,
    ]


def generate_csv_report(
    classified_findings: list[ClassifiedFinding],
    scanned_at: str | None = None,
) -> str:
    """
    Generate a CSV string from classified secret scan findings.

    Args:
        classified_findings: Output from classifiers.classify_all().
        scanned_at:          Timestamp string to embed in each row.
                             Defaults to the current UTC time.

    Returns:
        UTF-8 BOM-prefixed CSV string with a header row followed by one
        row per finding. Returns headers-only CSV if no findings.
    """
    if scanned_at is None:
        scanned_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    output = io.StringIO()
    # UTF-8 BOM for Excel compatibility
    output.write("\ufeff")

    writer = csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow(_HEADERS)

    for cf in classified_findings:
        writer.writerow(_finding_to_row(cf, scanned_at))

    return output.getvalue()


def save_csv_report(
    csv_text: str,
    output_dir: str | Path,
) -> Path:
    """
    Save a CSV report to the output directory.

    Args:
        csv_text:   CSV string from generate_csv_report().
        output_dir: Directory to write the report file.

    Returns:
        Path to the written .csv file.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_path = out / f"secret_scan_{timestamp}.csv"
    # Write without BOM-stripping — the BOM is already in csv_text
    report_path.write_text(csv_text, encoding="utf-8-sig")
    return report_path
