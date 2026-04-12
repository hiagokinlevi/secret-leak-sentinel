"""
Criticality Classifier
========================
Assigns a final criticality and confidence score to a finding by combining
signals from multiple detectors.

The classifier reconciles situations where:
  - Both the regex detector and entropy detector flag the same line
  - A regex finding has low confidence but entropy confirms the value is non-trivial
  - A finding occurs in a context that reduces its likelihood (e.g., a test fixture)

Inputs
------
- Primary regex Finding (always required)
- Optional EntropyFinding for the same file and line
- File path context (is this a test file? a sample directory? a .env file?)

Outputs
-------
- Classified criticality (may be escalated or de-escalated relative to the regex pattern)
- Adjusted confidence score (0.0 to 1.0)
- Classification rationale string (for report display)
- Cross-file corroboration metadata when the same entropy token appears in multiple files
"""
from dataclasses import dataclass
from typing import Optional

from classifiers.context_analyzer import analyze_context
from classifiers.cross_file_correlation import (
    CrossFileCorrelation,
    correlate_entropy_findings,
)
from detectors.regex_detector import Criticality, Finding, SecretType
from detectors.entropy_detector import EntropyFinding


@dataclass
class ClassifiedFinding:
    """A finding enriched with classification metadata."""
    original_finding: Finding
    final_criticality: Criticality
    confidence: float               # 0.0 to 1.0
    rationale: str                  # Human-readable explanation of the classification
    entropy_corroboration: bool     # True if an entropy finding corroborates the regex finding
    context_penalty: bool           # True if context reduced the confidence (e.g., test file)
    context_escalation: bool        # True if context raised confidence (e.g., .env file)
    context_labels: tuple[str, ...] = ()  # Explicit context labels used during classification
    cross_file_corroboration: bool = False
    correlated_file_count: int = 1


def classify_finding(
    finding: Finding,
    entropy_finding: Optional[EntropyFinding] = None,
    correlated_file_count: int = 1,
) -> ClassifiedFinding:
    """
    Classify a regex finding, optionally corroborated by an entropy finding.

    Args:
        finding: The primary regex detector finding.
        entropy_finding: Optional entropy finding for the same file and line.
                         If provided and entropy is above threshold, confidence is boosted.
        correlated_file_count: Number of distinct files that share the same
                               corroborating entropy token fingerprint.

    Returns:
        ClassifiedFinding with adjusted criticality and confidence.
    """
    criticality = finding.criticality
    confidence = finding.confidence
    rationale_parts: list[str] = [
        f"Regex pattern '{finding.detector_name}' matched at line {finding.line_number}."
    ]
    entropy_corroborated = False
    cross_file_corroborated = False
    context = analyze_context(finding.file_path)
    correlated_file_count = max(correlated_file_count, 1)

    # --- Entropy corroboration ---
    if entropy_finding and entropy_finding.line_number == finding.line_number:
        # Entropy corroborates the regex finding: the matched value is also high-entropy,
        # reducing the likelihood of a false positive.
        entropy_boost = min(entropy_finding.entropy / 10.0, 0.15)  # Up to +0.15 confidence
        confidence = min(confidence + entropy_boost, 0.98)
        entropy_corroborated = True
        rationale_parts.append(
            f"Entropy detector corroborates ({entropy_finding.entropy:.2f} bits/char); "
            f"confidence boosted."
        )

        if correlated_file_count > 1:
            correlation_boost = min(0.04 + 0.02 * (correlated_file_count - 1), 0.12)
            confidence = min(confidence + correlation_boost, 0.98)
            cross_file_corroborated = True
            rationale_parts.append(
                f"Same high-entropy token fingerprint recurs across {correlated_file_count} files; "
                f"cross-file confidence boosted."
            )

    # --- Context analysis ---
    confidence = min(max(confidence + context.confidence_delta, 0.10), 0.98)
    rationale_parts.extend(context.rationale_parts)

    if context.promote_high_to_critical and criticality == Criticality.HIGH:
        criticality = Criticality.CRITICAL
        rationale_parts.append("Criticality escalated from HIGH to CRITICAL due to file context.")

    if context.demote_critical_to_high:
        if criticality == Criticality.CRITICAL:
            criticality = Criticality.HIGH
            rationale_parts.append("Criticality de-escalated from CRITICAL to HIGH in sample context.")

    rationale = " ".join(rationale_parts)

    return ClassifiedFinding(
        original_finding=finding,
        final_criticality=criticality,
        confidence=round(confidence, 3),
        rationale=rationale,
        entropy_corroboration=entropy_corroborated,
        context_penalty=context.is_penalty,
        context_escalation=context.is_escalation,
        context_labels=context.labels,
        cross_file_corroboration=cross_file_corroborated,
        correlated_file_count=correlated_file_count if cross_file_corroborated else 1,
    )


def _apply_cross_file_correlation(
    classified: ClassifiedFinding,
    correlation: CrossFileCorrelation,
) -> ClassifiedFinding:
    """Boost a classified finding when the same entropy token appears in multiple files."""
    criticality = classified.final_criticality
    confidence = classified.confidence
    rationale_parts = [classified.rationale]

    if correlation.distinct_file_count >= 3 and criticality == Criticality.HIGH:
        criticality = Criticality.CRITICAL
        rationale_parts.append(
            "Criticality escalated from HIGH to CRITICAL because the masked token "
            "was reused across three or more files."
        )
    elif correlation.distinct_file_count >= 2 and criticality == Criticality.MEDIUM:
        criticality = Criticality.HIGH
        rationale_parts.append(
            "Criticality escalated from MEDIUM to HIGH because the masked token "
            "was reused across multiple files."
        )

    correlation_boost = 0.08 + 0.03 * max(correlation.distinct_file_count - 2, 0)
    confidence = min(confidence + correlation_boost, 0.99)
    rationale_parts.append(
        "Cross-file entropy correlation confirmed the same masked token "
        f"(fp={correlation.short_fingerprint}) in {correlation.distinct_file_count} files."
    )

    return ClassifiedFinding(
        original_finding=classified.original_finding,
        final_criticality=criticality,
        confidence=round(confidence, 3),
        rationale=" ".join(rationale_parts),
        entropy_corroboration=classified.entropy_corroboration,
        context_penalty=classified.context_penalty,
        context_escalation=classified.context_escalation,
        context_labels=classified.context_labels,
    )


def _build_synthetic_entropy_finding(
    entropy_finding: EntropyFinding,
    correlation: CrossFileCorrelation,
) -> Finding:
    """Create a synthetic regex-like finding for entropy-only cross-file reuse."""
    excerpt = (
        f"{entropy_finding.masked_excerpt} "
        f"[reused across {correlation.distinct_file_count} files fp={correlation.short_fingerprint}]"
    )[:120]
    return Finding(
        detector_name="cross_file_entropy_reuse",
        secret_type=SecretType.GENERIC_SECRET,
        criticality=Criticality.MEDIUM,
        file_path=entropy_finding.file_path,
        line_number=entropy_finding.line_number,
        masked_excerpt=excerpt,
        confidence=0.70,
    )


def classify_all(
    regex_findings: list[Finding],
    entropy_findings: list[EntropyFinding],
) -> list[ClassifiedFinding]:
    """
    Classify all regex findings, corroborating with entropy findings where possible.

    Attempts to match each regex finding with an entropy finding from the same
    file and line. Unmatched regex findings are classified without corroboration.

    Args:
        regex_findings: All regex detector findings from a scan.
        entropy_findings: All entropy detector findings from the same scan.

    Returns:
        List of ClassifiedFinding objects, sorted by criticality (critical first).
    """
    # Build a lookup from (file_path, line_number) -> EntropyFinding for fast matching.
    entropy_index: dict[tuple[str, int], EntropyFinding] = {}
    correlated_files: dict[str, set[str]] = {}
    for ef in entropy_findings:
        key = (ef.file_path, ef.line_number)
        # If multiple entropy findings on the same line, keep the highest-entropy one
        if key not in entropy_index or ef.entropy > entropy_index[key].entropy:
            entropy_index[key] = ef
        if ef.token_fingerprint:
            correlated_files.setdefault(ef.token_fingerprint, set()).add(ef.file_path)

    correlation_index: dict[tuple[str, int], CrossFileCorrelation] = {}
    for correlation in correlate_entropy_findings(entropy_findings):
        for finding in correlation.findings:
            correlation_index[(finding.file_path, finding.line_number)] = correlation

    classified: list[ClassifiedFinding] = []
    covered_keys: set[tuple[str, int]] = set()
    for finding in regex_findings:
        key = (finding.file_path, finding.line_number)
        corroborating_entropy = entropy_index.get(key)
        correlated_file_count = 1
        if corroborating_entropy and corroborating_entropy.token_fingerprint:
            correlated_file_count = len(
                correlated_files.get(
                    corroborating_entropy.token_fingerprint,
                    {corroborating_entropy.file_path},
                )
            )
        classified.append(
            classify_finding(
                finding,
                corroborating_entropy,
                correlated_file_count=correlated_file_count,
            )
        )

    # Sort by criticality: critical > high > medium > low
    criticality_order = {
        Criticality.CRITICAL: 0,
        Criticality.HIGH: 1,
        Criticality.MEDIUM: 2,
        Criticality.LOW: 3,
    }
    classified.sort(key=lambda c: criticality_order.get(c.final_criticality, 99))
    return classified
