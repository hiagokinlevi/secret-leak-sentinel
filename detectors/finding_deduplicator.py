"""
Multi-Detector Finding Deduplicator
=====================================
When multiple secret detectors (entropy, regex, custom patterns) fire on
the same file and overlapping line ranges, they produce duplicate findings
that inflate alert counts and confuse remediation workflows.

This module provides:
  - FindingDeduplicator: Merges overlapping findings from multiple detectors
    into a canonical set with combined confidence and attribution.
  - DeduplicatedFinding: A merged finding with provenance metadata.
  - DeduplicationReport: Aggregated statistics and the final finding set.

Overlap Detection
------------------
Two findings overlap when they share the same file_path AND one of:
  (a) Same rule_id
  (b) Overlapping line range (line numbers within ``overlap_window`` lines)
  (c) Same evidence hash / fingerprint

Merge Strategy
---------------
When findings overlap:
  - rule_ids:      Union of all contributing rule IDs.
  - detectors:     Union of all contributing detector names.
  - severity:      Maximum severity across all contributors.
  - confidence:    Combined confidence = 1 - ∏(1 - cᵢ) (probability union).
  - evidence:      Longest (most specific) evidence string.
  - line_range:    Spanning range of all overlapping findings.
  - fingerprint:   Re-computed from the canonical evidence.

Usage::

    from detectors.finding_deduplicator import FindingDeduplicator

    deduper = FindingDeduplicator()
    report = deduper.deduplicate(all_findings)
    print(report.summary())
    for finding in report.deduplicated_findings:
        print(finding.to_dict())
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
    "UNKNOWN":  0,
}


def _max_severity(severities: list[str]) -> str:
    """Return the highest severity from a list."""
    if not severities:
        return "UNKNOWN"
    return max(severities, key=lambda s: _SEVERITY_ORDER.get(s.upper(), 0))


def _combined_confidence(confidences: list[float]) -> float:
    """
    Combine independent confidence scores using the probability union formula:
        P(A ∪ B) = 1 - ∏(1 - Pᵢ)

    This ensures that two detectors each firing at 50% confidence produces
    75% combined confidence, not 50% or 100%.
    """
    if not confidences:
        return 0.0
    result = 1.0
    for c in confidences:
        result *= 1.0 - max(0.0, min(1.0, c))
    return round(1.0 - result, 4)


def _fingerprint(rule_id: str, file_path: str, evidence: str) -> str:
    """Compute a 64-character SHA-256 fingerprint."""
    raw = f"{rule_id}:{file_path}:{evidence}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DeduplicatedFinding:
    """
    A canonical finding produced by merging one or more overlapping raw findings.

    Attributes:
        fingerprint:         Stable identifier (SHA-256 of canonical rule+path+evidence).
        rule_ids:            Union of rule IDs from contributing findings.
        detectors:           Union of detector names that contributed.
        file_path:           File where the secret was found.
        line_start:          First line of the spanning range.
        line_end:            Last line of the spanning range.
        evidence:            Longest (most specific) evidence string.
        severity:            Maximum severity across contributors.
        confidence:          Combined confidence (probability union).
        source_count:        Number of raw findings merged into this one.
        suppressed:          True if all contributing findings were suppressed.
        tags:                Key-value annotations carried over from raw findings.
    """
    fingerprint:  str
    rule_ids:     set[str]
    detectors:    set[str]
    file_path:    str
    line_start:   Optional[int]
    line_end:     Optional[int]
    evidence:     str
    severity:     str
    confidence:   float
    source_count: int = 1
    suppressed:   bool = False
    tags:         dict[str, Any] = field(default_factory=dict)

    @property
    def primary_rule_id(self) -> str:
        """Return the lexicographically first rule_id as the canonical identifier."""
        return min(self.rule_ids) if self.rule_ids else "UNKNOWN"

    def summary(self) -> str:
        rules = ",".join(sorted(self.rule_ids))
        dets  = ",".join(sorted(self.detectors))
        line_str = (
            f"L{self.line_start}–{self.line_end}"
            if self.line_start is not None and self.line_end is not None
            else "L?"
        )
        return (
            f"[{self.severity}] {self.file_path}:{line_str} | "
            f"rules=[{rules}] detectors=[{dets}] | "
            f"confidence={self.confidence:.2f} sources={self.source_count}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint":   self.fingerprint,
            "primary_rule_id": self.primary_rule_id,
            "rule_ids":      sorted(self.rule_ids),
            "detectors":     sorted(self.detectors),
            "file_path":     self.file_path,
            "line_start":    self.line_start,
            "line_end":      self.line_end,
            "evidence":      self.evidence,
            "severity":      self.severity,
            "confidence":    self.confidence,
            "source_count":  self.source_count,
            "suppressed":    self.suppressed,
            "tags":          self.tags,
        }


@dataclass
class DeduplicationReport:
    """
    Aggregated result of a deduplication pass.

    Attributes:
        deduplicated_findings: Final canonical finding set.
        input_count:           Total raw findings before dedup.
        output_count:          Unique findings after dedup.
        merged_count:          Findings that were merged (input - output).
        suppressed_count:      Findings flagged as suppressed.
    """
    deduplicated_findings: list[DeduplicatedFinding] = field(default_factory=list)
    input_count:    int = 0
    output_count:   int = 0
    merged_count:   int = 0
    suppressed_count: int = 0

    @property
    def dedup_ratio(self) -> float:
        """Fraction of input findings removed by deduplication."""
        if self.input_count == 0:
            return 0.0
        return round(self.merged_count / self.input_count, 3)

    def summary(self) -> str:
        return (
            f"DeduplicationReport: "
            f"{self.input_count} in → {self.output_count} out | "
            f"{self.merged_count} merged ({self.dedup_ratio:.0%} reduction) | "
            f"{self.suppressed_count} suppressed"
        )

    def by_severity(self, severity: str) -> list[DeduplicatedFinding]:
        return [
            f for f in self.deduplicated_findings
            if f.severity.upper() == severity.upper()
        ]

    def by_file(self, file_path: str) -> list[DeduplicatedFinding]:
        return [f for f in self.deduplicated_findings if f.file_path == file_path]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get(d: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in d:
            return d[key]
    return default


def _get_str(d: dict[str, Any], *keys: str) -> str:
    val = _get(d, *keys, default="")
    return str(val).strip() if val else ""


def _get_int(d: dict[str, Any], *keys: str) -> Optional[int]:
    val = _get(d, *keys)
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _lines_overlap(
    a_start: Optional[int],
    a_end:   Optional[int],
    b_start: Optional[int],
    b_end:   Optional[int],
    window:  int,
) -> bool:
    """Return True if the two line ranges overlap within ``window`` lines."""
    if any(x is None for x in (a_start, a_end, b_start, b_end)):
        return False
    assert a_start is not None and a_end is not None
    assert b_start is not None and b_end is not None
    return (a_start - window) <= b_end and (b_start - window) <= a_end


# ---------------------------------------------------------------------------
# FindingDeduplicator
# ---------------------------------------------------------------------------

class FindingDeduplicator:
    """
    Merges overlapping findings from multiple detectors into a canonical set.

    Two findings are considered duplicates when they share the same
    ``file_path`` AND at least one of:
      - Same ``fingerprint`` field (if present)
      - Same ``rule_id``
      - Overlapping line ranges (within ``overlap_window``)

    Args:
        overlap_window: Lines of tolerance for line-range overlap.
                        Default 2 (findings within 2 lines are merged).
    """

    def __init__(self, overlap_window: int = 2) -> None:
        self._window = overlap_window

    def deduplicate(
        self,
        findings: list[dict[str, Any]],
    ) -> DeduplicationReport:
        """
        Deduplicate a list of raw finding dicts.

        Each finding should have:
          - rule_id      (str)
          - file_path    (str)
          - evidence / matched_text  (str, optional)
          - line_number / line_start / line  (int, optional)
          - line_end     (int, optional)
          - severity     (str, optional)
          - confidence   (float 0–1, optional)
          - detector     (str, optional) — detector name
          - fingerprint  (str, optional) — pre-computed fingerprint
          - suppressed   (bool, optional)

        Returns a DeduplicationReport.
        """
        if not findings:
            return DeduplicationReport(
                input_count=0, output_count=0, merged_count=0
            )

        # Normalise all findings into groups
        groups: list[list[dict[str, Any]]] = self._group_overlapping(findings)

        deduped: list[DeduplicatedFinding] = [
            self._merge_group(group) for group in groups
        ]

        suppressed = sum(1 for f in deduped if f.suppressed)
        merged     = len(findings) - len(deduped)

        return DeduplicationReport(
            deduplicated_findings=deduped,
            input_count=len(findings),
            output_count=len(deduped),
            merged_count=max(0, merged),
            suppressed_count=suppressed,
        )

    # ------------------------------------------------------------------
    # Grouping logic
    # ------------------------------------------------------------------

    def _group_overlapping(
        self,
        findings: list[dict[str, Any]],
    ) -> list[list[dict[str, Any]]]:
        """
        Union-find grouping of findings that overlap.

        Two findings overlap when they share file_path AND:
          - Same fingerprint OR same rule_id OR overlapping line ranges.
        """
        n = len(findings)
        parent = list(range(n))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x: int, y: int) -> None:
            parent[find(x)] = find(y)

        for i in range(n):
            for j in range(i + 1, n):
                if self._should_merge(findings[i], findings[j]):
                    union(i, j)

        # Collect groups
        groups: dict[int, list[dict[str, Any]]] = {}
        for idx, finding in enumerate(findings):
            root = find(idx)
            groups.setdefault(root, []).append(finding)

        return list(groups.values())

    def _should_merge(self, a: dict[str, Any], b: dict[str, Any]) -> bool:
        """Return True if two findings should be merged."""
        # Must be in the same file
        if _get_str(a, "file_path") != _get_str(b, "file_path"):
            return False
        if not _get_str(a, "file_path"):
            return False

        # Same fingerprint — definitive match
        fp_a = _get_str(a, "fingerprint")
        fp_b = _get_str(b, "fingerprint")
        if fp_a and fp_b and fp_a == fp_b:
            return True

        # Same rule_id — likely the same check from different detectors
        if _get_str(a, "rule_id") == _get_str(b, "rule_id") and _get_str(a, "rule_id"):
            return True

        # Overlapping line ranges
        a_start = _get_int(a, "line_start", "line_number", "line")
        a_end   = _get_int(a, "line_end") or a_start
        b_start = _get_int(b, "line_start", "line_number", "line")
        b_end   = _get_int(b, "line_end") or b_start
        if _lines_overlap(a_start, a_end, b_start, b_end, self._window):
            return True

        return False

    # ------------------------------------------------------------------
    # Merge strategy
    # ------------------------------------------------------------------

    def _merge_group(self, group: list[dict[str, Any]]) -> DeduplicatedFinding:
        """Merge a group of overlapping findings into one canonical finding."""
        rule_ids:   set[str] = set()
        detectors:  set[str] = set()
        severities: list[str] = []
        confidences: list[float] = []
        evidences:  list[str] = []
        line_starts: list[int] = []
        line_ends:   list[int] = []
        suppressed_flags: list[bool] = []
        tags: dict[str, Any] = {}

        file_path = _get_str(group[0], "file_path")

        for f in group:
            if rid := _get_str(f, "rule_id"):
                rule_ids.add(rid)
            if det := _get_str(f, "detector", "source"):
                detectors.add(det)
            if sev := _get_str(f, "severity"):
                severities.append(sev.upper())
            raw_conf = f.get("confidence")
            if raw_conf is not None:
                try:
                    confidences.append(float(raw_conf))
                except (TypeError, ValueError):
                    pass
            if ev := _get_str(f, "evidence", "matched_text", "value"):
                evidences.append(ev)
            if ls := _get_int(f, "line_start", "line_number", "line"):
                line_starts.append(ls)
            le = _get_int(f, "line_end") or _get_int(f, "line_start", "line_number", "line")
            if le:
                line_ends.append(le)
            suppressed_flags.append(bool(f.get("suppressed", False)))
            # Carry over any extra tags
            for k, v in f.items():
                if k not in ("rule_id", "file_path", "evidence", "severity",
                             "confidence", "line_start", "line_end", "line_number",
                             "line", "detector", "fingerprint", "suppressed"):
                    tags[k] = v

        # Canonical evidence: longest string (most specific)
        canonical_evidence = max(evidences, key=len) if evidences else ""

        # Canonical rule: lexicographic minimum for stability
        canonical_rule = min(rule_ids) if rule_ids else "UNKNOWN"

        fp = _fingerprint(canonical_rule, file_path, canonical_evidence)

        return DeduplicatedFinding(
            fingerprint=fp,
            rule_ids=rule_ids if rule_ids else {"UNKNOWN"},
            detectors=detectors,
            file_path=file_path,
            line_start=min(line_starts) if line_starts else None,
            line_end=max(line_ends) if line_ends else None,
            evidence=canonical_evidence,
            severity=_max_severity(severities),
            confidence=_combined_confidence(confidences) if confidences else 0.0,
            source_count=len(group),
            suppressed=all(suppressed_flags),
            tags=tags,
        )
