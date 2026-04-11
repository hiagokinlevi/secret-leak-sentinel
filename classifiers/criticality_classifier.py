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
"""
from dataclasses import dataclass
from typing import Optional

from classifiers.context_analyzer import analyze_context
from detectors.regex_detector import Criticality, Finding
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
    context_labels: tuple[str, ...]  # Explicit context labels used during classification


def classify_finding(
    finding: Finding,
    entropy_finding: Optional[EntropyFinding] = None,
) -> ClassifiedFinding:
    """
    Classify a regex finding, optionally corroborated by an entropy finding.

    Args:
        finding: The primary regex detector finding.
        entropy_finding: Optional entropy finding for the same file and line.
                         If provided and entropy is above threshold, confidence is boosted.

    Returns:
        ClassifiedFinding with adjusted criticality and confidence.
    """
    criticality = finding.criticality
    confidence = finding.confidence
    rationale_parts: list[str] = [
        f"Regex pattern '{finding.detector_name}' matched at line {finding.line_number}."
    ]
    entropy_corroborated = False
    context = analyze_context(finding.file_path)

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
    # Build a lookup from (file_path, line_number) -> EntropyFinding for fast matching
    entropy_index: dict[tuple[str, int], EntropyFinding] = {}
    for ef in entropy_findings:
        key = (ef.file_path, ef.line_number)
        # If multiple entropy findings on the same line, keep the highest-entropy one
        if key not in entropy_index or ef.entropy > entropy_index[key].entropy:
            entropy_index[key] = ef

    classified: list[ClassifiedFinding] = []
    for finding in regex_findings:
        key = (finding.file_path, finding.line_number)
        corroborating_entropy = entropy_index.get(key)
        classified.append(classify_finding(finding, corroborating_entropy))

    # Sort by criticality: critical > high > medium > low
    criticality_order = {
        Criticality.CRITICAL: 0,
        Criticality.HIGH: 1,
        Criticality.MEDIUM: 2,
        Criticality.LOW: 3,
    }
    classified.sort(key=lambda c: criticality_order.get(c.final_criticality, 99))
    return classified
