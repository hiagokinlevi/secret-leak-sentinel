"""
Cross-file entropy correlation
==============================
Promotes repeated high-entropy tokens that appear across multiple files.

Exact raw token reuse is tracked via a non-reversible token fingerprint produced
by the entropy detector. This keeps the scan output masked while still allowing
the classifier and reports to identify likely secret propagation.
"""
from __future__ import annotations

from dataclasses import dataclass

from detectors.entropy_detector import EntropyFinding


@dataclass(frozen=True)
class CrossFileCorrelation:
    """A masked high-entropy token that appears in multiple files."""

    token_fingerprint: str
    masked_token: str
    distinct_file_count: int
    occurrence_count: int
    file_paths: tuple[str, ...]
    findings: tuple[EntropyFinding, ...]

    @property
    def short_fingerprint(self) -> str:
        return self.token_fingerprint[:12]


def correlate_entropy_findings(
    entropy_findings: list[EntropyFinding],
    min_distinct_files: int = 2,
) -> list[CrossFileCorrelation]:
    """
    Group entropy findings by token fingerprint and return only cross-file reuse.

    Findings with no stored fingerprint fall back to the masked token so tests or
    older payloads still participate in correlation.
    """
    grouped: dict[str, list[EntropyFinding]] = {}
    for finding in entropy_findings:
        key = finding.token_fingerprint or finding.token
        grouped.setdefault(key, []).append(finding)

    correlations: list[CrossFileCorrelation] = []
    for fingerprint, grouped_findings in grouped.items():
        file_paths = tuple(sorted({finding.file_path for finding in grouped_findings}))
        if len(file_paths) < min_distinct_files:
            continue

        ordered_findings = tuple(
            sorted(
                grouped_findings,
                key=lambda finding: (finding.file_path, finding.line_number, -finding.entropy),
            )
        )
        correlations.append(
            CrossFileCorrelation(
                token_fingerprint=fingerprint,
                masked_token=ordered_findings[0].token,
                distinct_file_count=len(file_paths),
                occurrence_count=len(ordered_findings),
                file_paths=file_paths,
                findings=ordered_findings,
            )
        )

    correlations.sort(
        key=lambda correlation: (
            -correlation.distinct_file_count,
            -correlation.occurrence_count,
            correlation.masked_token,
        )
    )
    return correlations
