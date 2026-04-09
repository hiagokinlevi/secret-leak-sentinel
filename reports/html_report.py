"""
HTML Scan Report Generator
============================
Generates a self-contained HTML report from secret scan results.
The report requires no external CSS or JavaScript — everything is inlined.

Report sections:
  - Header with scan metadata (path, timestamp, total counts)
  - Severity badge summary bar
  - Critical and High findings as expandable cards
  - Medium and Low findings in a compact table
  - Entropy findings summary table
  - Remediation tips footer

Usage:
    from reports.html_report import generate_html_report, save_html_report
    from classifiers.criticality_classifier import ClassifiedFinding

    html = generate_html_report(classified_findings, scan_path="./my-repo")
    path = save_html_report(html, output_dir="./scan-results")
"""
from __future__ import annotations

import html as _html
from datetime import datetime
from pathlib import Path
from typing import Optional

from classifiers.criticality_classifier import ClassifiedFinding
from detectors.entropy_detector import EntropyFinding
from detectors.regex_detector import Criticality


# ---------------------------------------------------------------------------
# HTML escaping helper
# ---------------------------------------------------------------------------

def _e(text: str) -> str:
    """HTML-escape a string."""
    return _html.escape(str(text), quote=True)


# ---------------------------------------------------------------------------
# Severity styling
# ---------------------------------------------------------------------------

_BADGE_COLORS: dict[Criticality, tuple[str, str]] = {
    Criticality.CRITICAL: ("#b91c1c", "#fee2e2"),   # text, background
    Criticality.HIGH:     ("#c2410c", "#ffedd5"),
    Criticality.MEDIUM:   ("#92400e", "#fef9c3"),
    Criticality.LOW:      ("#1d4ed8", "#dbeafe"),
}

_CARD_BORDER: dict[Criticality, str] = {
    Criticality.CRITICAL: "#ef4444",
    Criticality.HIGH:     "#f97316",
    Criticality.MEDIUM:   "#eab308",
    Criticality.LOW:      "#3b82f6",
}


def _badge(criticality: Criticality) -> str:
    """Return an inline-styled severity badge span."""
    text_color, bg_color = _BADGE_COLORS[criticality]
    label = criticality.value.upper()
    return (
        f'<span style="background:{bg_color};color:{text_color};'
        f'padding:2px 8px;border-radius:4px;font-size:0.75rem;'
        f'font-weight:700;letter-spacing:0.05em;">{label}</span>'
    )


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
    font-size: 14px; background: #f8fafc; color: #1e293b; line-height: 1.6;
  }
  .page { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }
  h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 4px; }
  h2 { font-size: 1.1rem; font-weight: 600; margin: 32px 0 12px; color: #334155; }
  .meta { color: #64748b; font-size: 0.85rem; margin-bottom: 24px; }
  .summary-bar {
    display: flex; gap: 16px; flex-wrap: wrap;
    background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
    padding: 16px 20px; margin-bottom: 32px;
  }
  .count-chip {
    display: flex; flex-direction: column; align-items: center;
    min-width: 80px; padding: 8px 12px;
    border-radius: 6px; border: 1px solid #e2e8f0;
  }
  .count-num { font-size: 1.6rem; font-weight: 700; }
  .count-label { font-size: 0.7rem; font-weight: 600; letter-spacing: 0.05em; }
  .finding-card {
    background: #fff; border-radius: 8px;
    border-left: 4px solid #94a3b8; border: 1px solid #e2e8f0;
    margin-bottom: 16px; padding: 16px 20px;
  }
  .finding-header {
    display: flex; gap: 10px; align-items: baseline;
    margin-bottom: 8px; flex-wrap: wrap;
  }
  .finding-loc { color: #64748b; font-size: 0.82rem; font-family: monospace; }
  .finding-excerpt {
    background: #f1f5f9; border-radius: 4px;
    padding: 8px 12px; font-family: monospace; font-size: 0.8rem;
    white-space: pre-wrap; word-break: break-all;
    margin: 8px 0; border: 1px solid #e2e8f0;
  }
  .finding-rationale { color: #475569; font-size: 0.82rem; margin-top: 6px; }
  table {
    width: 100%; border-collapse: collapse;
    background: #fff; border-radius: 8px;
    border: 1px solid #e2e8f0; overflow: hidden;
  }
  th {
    background: #f8fafc; text-align: left;
    padding: 8px 12px; font-size: 0.78rem;
    font-weight: 600; letter-spacing: 0.04em;
    color: #64748b; border-bottom: 1px solid #e2e8f0;
  }
  td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; font-size: 0.83rem; }
  tr:last-child td { border-bottom: none; }
  .mono { font-family: monospace; font-size: 0.78rem; }
  .clean-banner {
    background: #f0fdf4; border: 1px solid #86efac;
    border-radius: 8px; padding: 20px; text-align: center;
    color: #166534; font-weight: 600; margin-bottom: 32px;
  }
  footer { color: #94a3b8; font-size: 0.75rem; margin-top: 40px; text-align: center; }
"""


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

def _summary_bar(classified_findings: list[ClassifiedFinding]) -> str:
    counts: dict[Criticality, int] = {c: 0 for c in Criticality}
    for cf in classified_findings:
        counts[cf.final_criticality] += 1

    chips = ""
    for crit in (Criticality.CRITICAL, Criticality.HIGH, Criticality.MEDIUM, Criticality.LOW):
        text_color, bg_color = _BADGE_COLORS[crit]
        chips += (
            f'<div class="count-chip" style="background:{bg_color};border-color:{text_color}20;">'
            f'<span class="count-num" style="color:{text_color};">{counts[crit]}</span>'
            f'<span class="count-label" style="color:{text_color};">{crit.value.upper()}</span>'
            f"</div>\n"
        )
    total_chip = (
        '<div class="count-chip">'
        f'<span class="count-num">{len(classified_findings)}</span>'
        '<span class="count-label" style="color:#64748b;">TOTAL</span>'
        "</div>\n"
    )
    return f'<div class="summary-bar">{total_chip}{chips}</div>\n'


def _finding_card(cf: ClassifiedFinding, index: int) -> str:
    f = cf.original_finding
    border_color = _CARD_BORDER.get(cf.final_criticality, "#94a3b8")
    entropy_tag = ""
    if cf.entropy_corroboration:
        entropy_tag = (
            ' <span style="background:#dbeafe;color:#1d4ed8;padding:1px 6px;'
            'border-radius:3px;font-size:0.7rem;">entropy+</span>'
        )
    context_tag = ""
    if cf.context_penalty:
        context_tag = (
            ' <span style="background:#f1f5f9;color:#64748b;padding:1px 6px;'
            'border-radius:3px;font-size:0.7rem;">low-risk ctx</span>'
        )

    return (
        f'<div class="finding-card" style="border-left-color:{border_color};">\n'
        f'  <div class="finding-header">\n'
        f"    {_badge(cf.final_criticality)}\n"
        f"    {entropy_tag}{context_tag}\n"
        f'    <span style="font-weight:600;">{_e(f.detector_name)}</span>\n'
        f"  </div>\n"
        f'  <div class="finding-loc">'
        f"{_e(f.file_path)} &middot; line {f.line_number} &middot; "
        f"{_e(f.secret_type.value)} &middot; {cf.confidence:.0%} confidence"
        f"</div>\n"
        f'  <pre class="finding-excerpt">{_e(f.masked_excerpt)}</pre>\n'
        f'  <div class="finding-rationale">{_e(cf.rationale)}</div>\n'
        f"</div>\n"
    )


def _entropy_table(entropy_findings: list[EntropyFinding]) -> str:
    rows = ""
    for ef in entropy_findings[:30]:
        rows += (
            f"<tr>"
            f'<td class="mono">{_e(ef.file_path)}</td>'
            f"<td>{ef.line_number}</td>"
            f"<td>{ef.entropy:.2f}</td>"
            f'<td class="mono">{_e(ef.token)}</td>'
            f"<td>{ef.confidence:.0%}</td>"
            f"</tr>\n"
        )
    if len(entropy_findings) > 30:
        rows += (
            f'<tr><td colspan="5" style="color:#64748b;font-style:italic;">'
            f"... and {len(entropy_findings) - 30} more</td></tr>\n"
        )
    return (
        '<table>\n'
        '<thead><tr>'
        "<th>File</th><th>Line</th><th>Entropy</th><th>Token (masked)</th><th>Confidence</th>"
        "</tr></thead>\n"
        f"<tbody>{rows}</tbody>\n"
        "</table>\n"
    )


def _medium_low_table(findings: list[ClassifiedFinding]) -> str:
    rows = ""
    for cf in findings:
        f = cf.original_finding
        rows += (
            f"<tr>"
            f"<td>{_badge(cf.final_criticality)}</td>"
            f'<td class="mono">{_e(f.file_path)}</td>'
            f"<td>{f.line_number}</td>"
            f'<td class="mono">{_e(f.detector_name)}</td>'
            f"<td>{cf.confidence:.0%}</td>"
            f"</tr>\n"
        )
    return (
        '<table>\n'
        '<thead><tr>'
        "<th>Severity</th><th>File</th><th>Line</th><th>Detector</th><th>Confidence</th>"
        "</tr></thead>\n"
        f"<tbody>{rows}</tbody>\n"
        "</table>\n"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_html_report(
    classified_findings: list[ClassifiedFinding],
    scan_path: str = ".",
    entropy_findings: Optional[list[EntropyFinding]] = None,
) -> str:
    """
    Generate a self-contained HTML report from classified secret scan results.

    Args:
        classified_findings: Output from classifiers.classify_all().
        scan_path:           The directory that was scanned.
        entropy_findings:    Optional raw entropy findings for the entropy table.

    Returns:
        Complete HTML document as a string (no external dependencies).
    """
    entropy_findings = entropy_findings or []
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    body_parts: list[str] = []

    # Header
    body_parts.append(
        f'<div class="page">\n'
        f"<h1>Secret Leak Detection Report</h1>\n"
        f'<div class="meta">'
        f"Scan path: <code>{_e(scan_path)}</code> &nbsp;&middot;&nbsp; "
        f"Scanned at: {_e(now)}"
        f"</div>\n"
    )

    # Summary bar
    body_parts.append(_summary_bar(classified_findings))

    if not classified_findings and not entropy_findings:
        body_parts.append(
            '<div class="clean-banner">'
            "&#10003; No secrets detected. All clear."
            "</div>\n"
        )
    else:
        # Critical / High cards
        critical_high = [
            cf for cf in classified_findings
            if cf.final_criticality in (Criticality.CRITICAL, Criticality.HIGH)
        ]
        if critical_high:
            body_parts.append("<h2>Critical &amp; High Severity Findings</h2>\n")
            for i, cf in enumerate(critical_high, start=1):
                body_parts.append(_finding_card(cf, i))

        # Medium / Low table
        medium_low = [
            cf for cf in classified_findings
            if cf.final_criticality in (Criticality.MEDIUM, Criticality.LOW)
        ]
        if medium_low:
            body_parts.append("<h2>Medium &amp; Low Severity Findings</h2>\n")
            body_parts.append(_medium_low_table(medium_low))

        # Entropy table
        if entropy_findings:
            body_parts.append(
                f"<h2>Entropy Findings ({len(entropy_findings)} total)</h2>\n"
            )
            body_parts.append(_entropy_table(entropy_findings))

    # Footer
    body_parts.append(
        '<footer>Generated by '
        '<a href="https://github.com/hiagokinlevi/secret-leak-sentinel">'
        "secret-leak-sentinel</a>"
        f" &middot; {_e(now)}"
        "</footer>\n"
        "</div>\n"
    )

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="UTF-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>Secret Scan Report — {_e(scan_path)}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        + "".join(body_parts)
        + "</body>\n"
        "</html>\n"
    )


def save_html_report(
    html: str,
    output_dir: str | Path,
) -> Path:
    """
    Save an HTML report to the output directory.

    Args:
        html:       HTML string from generate_html_report().
        output_dir: Directory to write the report file.

    Returns:
        Path to the written .html file.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_path = out / f"secret_scan_{timestamp}.html"
    report_path.write_text(html, encoding="utf-8")
    return report_path
