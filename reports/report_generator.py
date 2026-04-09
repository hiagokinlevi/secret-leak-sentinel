"""
Scan Report Generator
======================
Generates a Markdown findings report from classified secret detection results.

Report sections:
  - Summary: total files, findings by severity, scan mode
  - Critical and High findings (detailed, with masked excerpts)
  - Medium and Low findings (summary table)
  - Entropy findings summary (if any)
  - Remediation guidance section

Usage
-----
    from reports.report_generator import generate_scan_report, save_scan_report
    from classifiers.criticality_classifier import ClassifiedFinding

    report_md = generate_scan_report(classified_findings, scan_path="./my-project")
    saved = save_scan_report(report_md, output_dir="./scan-results")
"""
from datetime import datetime
from pathlib import Path
from typing import Optional

from classifiers.criticality_classifier import ClassifiedFinding
from detectors.entropy_detector import EntropyFinding
from detectors.regex_detector import Criticality


# Remediation guidance per secret type
_REMEDIATION_GUIDES: dict[str, str] = {
    "aws_access_key": (
        "1. Immediately deactivate the key in the AWS IAM console.\n"
        "2. Create a new key and update all services that used the old one.\n"
        "3. Review CloudTrail logs for unauthorized API calls using the exposed key.\n"
        "4. Remove the key from the file and rewrite git history if it was committed."
    ),
    "github_token": (
        "1. Revoke the token in GitHub Settings > Developer settings > Personal access tokens.\n"
        "2. Review the token's recent activity in the GitHub audit log.\n"
        "3. Generate a new token with minimal required scopes.\n"
        "4. Remove the token from the file and rewrite git history if it was committed."
    ),
    "private_key": (
        "1. Revoke or rotate the private key with the issuing authority (CA, cloud provider, etc.).\n"
        "2. Remove the key material from the file.\n"
        "3. If committed, rewrite git history to remove the key from all commits.\n"
        "4. Audit any systems that trusted the certificate signed by this key."
    ),
    "connection_string": (
        "1. Rotate the database password immediately.\n"
        "2. Update the connection string in all services using the rotated password.\n"
        "3. Review database access logs for unauthorized queries.\n"
        "4. Store credentials in a secrets manager (AWS Secrets Manager, Azure Key Vault, etc.)."
    ),
    "default": (
        "1. Rotate or revoke the exposed credential.\n"
        "2. Remove the credential from the source file.\n"
        "3. If committed to git, rewrite history using git-filter-repo.\n"
        "4. Store secrets in environment variables or a secrets manager — never in source code."
    ),
}


def _get_remediation(secret_type_value: str) -> str:
    """Return remediation guidance for a given secret type."""
    # Map enum values to guidance keys
    type_map = {
        "aws_access_key": "aws_access_key",
        "aws_secret_key": "aws_access_key",  # Same process
        "github_token": "github_token",
        "private_key": "private_key",
        "connection_string": "connection_string",
    }
    key = type_map.get(secret_type_value, "default")
    return _REMEDIATION_GUIDES[key]


def _severity_color_label(criticality: Criticality) -> str:
    """Return a text severity label for Markdown output."""
    labels = {
        Criticality.CRITICAL: "CRITICAL",
        Criticality.HIGH: "HIGH",
        Criticality.MEDIUM: "MEDIUM",
        Criticality.LOW: "LOW",
    }
    return labels.get(criticality, criticality.value.upper())


def generate_scan_report(
    classified_findings: list[ClassifiedFinding],
    scan_path: str = ".",
    entropy_findings: Optional[list[EntropyFinding]] = None,
) -> str:
    """
    Generate a Markdown findings report from classified secret detection results.

    Args:
        classified_findings: Output from classifiers.classify_all().
        scan_path: The directory or git repo that was scanned.
        entropy_findings: Optional raw entropy findings for the summary section.

    Returns:
        Multi-line Markdown string.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    entropy_findings = entropy_findings or []

    # Count findings by severity
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for cf in classified_findings:
        counts[cf.final_criticality.value] = counts.get(cf.final_criticality.value, 0) + 1

    lines: list[str] = [
        "# Secret Leak Detection Report",
        "",
        f"**Scan path:** `{scan_path}`  ",
        f"**Scanned at:** {now}  ",
        f"**Total findings:** {len(classified_findings)}  ",
        f"**Entropy findings:** {len(entropy_findings)}  ",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| CRITICAL | {counts.get('critical', 0)} |",
        f"| HIGH     | {counts.get('high', 0)} |",
        f"| MEDIUM   | {counts.get('medium', 0)} |",
        f"| LOW      | {counts.get('low', 0)} |",
        "",
    ]

    if not classified_findings:
        lines += [
            "> No secrets detected.",
            "",
            "---",
            "",
            "_Report generated by [secret-leak-sentinel]"
            "(https://github.com/hiagokinlevi/secret-leak-sentinel)_",
        ]
        return "\n".join(lines)

    # Critical and High: full detail
    critical_high = [
        cf for cf in classified_findings
        if cf.final_criticality in (Criticality.CRITICAL, Criticality.HIGH)
    ]
    if critical_high:
        lines += ["---", "", "## Critical and High Severity Findings", ""]
        for i, cf in enumerate(critical_high, start=1):
            f = cf.original_finding
            lines += [
                f"### Finding {i}: [{_severity_color_label(cf.final_criticality)}] "
                f"`{f.detector_name}`",
                "",
                f"- **File:** `{f.file_path}`",
                f"- **Line:** {f.line_number}",
                f"- **Secret type:** {f.secret_type.value}",
                f"- **Confidence:** {cf.confidence:.0%}",
                f"- **Entropy corroboration:** {'Yes' if cf.entropy_corroboration else 'No'}",
                "",
                f"**Excerpt (masked):**",
                "",
                f"```",
                f"{f.masked_excerpt}",
                f"```",
                "",
                f"**Classifier rationale:** {cf.rationale}",
                "",
                "**Remediation:**",
                "",
            ]
            for step in _get_remediation(f.secret_type.value).splitlines():
                lines.append(step)
            lines.append("")

    # Medium and Low: summary table
    medium_low = [
        cf for cf in classified_findings
        if cf.final_criticality in (Criticality.MEDIUM, Criticality.LOW)
    ]
    if medium_low:
        lines += [
            "---",
            "",
            "## Medium and Low Severity Findings",
            "",
            "| # | Severity | File | Line | Detector | Confidence |",
            "|---|----------|------|------|----------|------------|",
        ]
        for i, cf in enumerate(medium_low, start=1):
            f = cf.original_finding
            lines.append(
                f"| {i} | {_severity_color_label(cf.final_criticality)} "
                f"| `{f.file_path}` | {f.line_number} "
                f"| `{f.detector_name}` | {cf.confidence:.0%} |"
            )
        lines.append("")

    # Entropy findings summary
    if entropy_findings:
        lines += [
            "---",
            "",
            "## Entropy Findings",
            "",
            f"{len(entropy_findings)} high-entropy string(s) detected by the entropy detector. "
            "These may represent secrets not covered by regex patterns. Review each one.",
            "",
            "| File | Line | Entropy | Token (masked) |",
            "|------|------|---------|----------------|",
        ]
        for ef in entropy_findings[:20]:  # Cap at 20 to keep the report readable
            lines.append(
                f"| `{ef.file_path}` | {ef.line_number} | {ef.entropy:.2f} | `{ef.token}` |"
            )
        if len(entropy_findings) > 20:
            lines.append(f"\n_... and {len(entropy_findings) - 20} more (see JSON output)._")
        lines.append("")

    # Footer
    lines += [
        "---",
        "",
        "_Report generated by [secret-leak-sentinel]"
        "(https://github.com/hiagokinlevi/secret-leak-sentinel)_",
    ]

    return "\n".join(lines)


def save_scan_report(report_markdown: str, output_dir: str | Path) -> Path:
    """
    Save a Markdown scan report to the output directory.

    Args:
        report_markdown: Markdown string from generate_scan_report().
        output_dir: Directory to write the report file.

    Returns:
        Path to the written file.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_path = out / f"secret_scan_{timestamp}.md"
    report_path.write_text(report_markdown, encoding="utf-8")

    return report_path
