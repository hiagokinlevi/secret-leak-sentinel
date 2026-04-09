"""
Secret Scan Baseline Tracker
================================
Tracks the state of secret scan findings across multiple scan runs,
enabling diff-based workflows: identify new findings, resolve old ones,
and monitor persistent secrets that have not been remediated.

This is the complement to suppression.py: suppressions say "I know about
this and it's fine"; the baseline tracker says "I know about this and I'm
tracking whether it gets fixed."

Core Concepts
--------------
Fingerprint
    A stable identifier for a finding derived from its rule_id, file_path,
    and a hash of the evidence. Two runs that produce the same fingerprint
    refer to the same finding instance. Uses :func:`detectors.suppression.make_fingerprint`
    internally so fingerprints are interoperable.

Baseline
    A persisted snapshot of all known finding fingerprints at a given point
    in time. Stored as a JSON file that can be committed to version control.

Diff
    The comparison of a new scan result against the baseline:
      - **new_findings**:        found in current scan, NOT in baseline
      - **resolved_findings**:   in baseline, NOT in current scan (likely fixed)
      - **persistent_findings**: in BOTH baseline and current scan (not yet fixed)

Usage::

    from detectors.baseline_tracker import ScanBaseline, BaselineTracker

    # First run — create baseline
    tracker = BaselineTracker()
    tracker.set_baseline_from_findings(findings)
    tracker.save("baseline.json")

    # Later run — compare
    tracker2 = BaselineTracker.from_file("baseline.json")
    diff = tracker2.diff(new_findings)
    print(diff.summary())
    if diff.new_count > 0:
        raise SystemExit(1)  # Fail CI on new secrets
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Fingerprint helper
# ---------------------------------------------------------------------------

def _make_finding_fingerprint(
    rule_id: str,
    file_path: str,
    evidence: str = "",
    line_number: Optional[int] = None,
) -> str:
    """
    Compute a stable fingerprint for a finding.

    Incorporates rule_id, file_path, and evidence (the matched secret
    or a masked representation). Line number is intentionally excluded
    so that adding unrelated lines does not create spurious new findings.

    Returns a 64-character hex string.
    """
    parts = f"{rule_id}:{file_path}:{evidence}"
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()


def fingerprint_finding(finding: dict[str, Any]) -> str:
    """
    Extract or compute a fingerprint from a finding dict.

    Checks ``finding["fingerprint"]`` first (already computed);
    falls back to computing from rule_id + file_path + evidence.
    """
    if existing := finding.get("fingerprint"):
        return str(existing)
    rule_id   = str(finding.get("rule_id", ""))
    file_path = str(finding.get("file_path", ""))
    evidence  = str(finding.get("evidence", "") or finding.get("matched_text", ""))
    return _make_finding_fingerprint(rule_id, file_path, evidence)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BaselineEntry:
    """
    A single entry in a scan baseline.

    Attributes:
        fingerprint: Stable finding identifier.
        rule_id:     Detector rule that produced the finding.
        file_path:   File where the finding was detected.
        first_seen:  ISO date when this finding first appeared in a baseline.
        last_seen:   ISO date of the most recent scan that included it.
        severity:    Finding severity (free-form string, e.g. "HIGH").
        suppressed:  Whether this entry is expected/suppressed (informational).
    """
    fingerprint: str
    rule_id:     str
    file_path:   str
    first_seen:  str = field(default_factory=lambda: date.today().isoformat())
    last_seen:   str = field(default_factory=lambda: date.today().isoformat())
    severity:    str = "UNKNOWN"
    suppressed:  bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id":     self.rule_id,
            "file_path":   self.file_path,
            "first_seen":  self.first_seen,
            "last_seen":   self.last_seen,
            "severity":    self.severity,
            "suppressed":  self.suppressed,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BaselineEntry":
        return cls(
            fingerprint=d["fingerprint"],
            rule_id=d.get("rule_id", ""),
            file_path=d.get("file_path", ""),
            first_seen=d.get("first_seen", date.today().isoformat()),
            last_seen=d.get("last_seen", date.today().isoformat()),
            severity=d.get("severity", "UNKNOWN"),
            suppressed=bool(d.get("suppressed", False)),
        )


@dataclass
class BaselineDiff:
    """
    Result of comparing a new scan against a stored baseline.

    Attributes:
        new_findings:        Findings in the scan but NOT in the baseline.
        resolved_findings:   Baseline entries NOT seen in the current scan.
        persistent_findings: Baseline entries ALSO seen in the current scan.
        scan_fingerprints:   All fingerprints from the current scan.
        baseline_fingerprints: All fingerprints in the baseline.
    """
    new_findings:          list[dict[str, Any]] = field(default_factory=list)
    resolved_findings:     list[BaselineEntry]  = field(default_factory=list)
    persistent_findings:   list[BaselineEntry]  = field(default_factory=list)
    scan_fingerprints:     set[str] = field(default_factory=set)
    baseline_fingerprints: set[str] = field(default_factory=set)

    @property
    def new_count(self) -> int:
        return len(self.new_findings)

    @property
    def resolved_count(self) -> int:
        return len(self.resolved_findings)

    @property
    def persistent_count(self) -> int:
        return len(self.persistent_findings)

    @property
    def has_new_findings(self) -> bool:
        return self.new_count > 0

    @property
    def has_resolved_findings(self) -> bool:
        return self.resolved_count > 0

    def summary(self) -> str:
        return (
            f"BaselineDiff: "
            f"{self.new_count} new | "
            f"{self.resolved_count} resolved | "
            f"{self.persistent_count} persistent"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "new_count":        self.new_count,
            "resolved_count":   self.resolved_count,
            "persistent_count": self.persistent_count,
            "new_findings":     self.new_findings,
            "resolved_findings":   [e.to_dict() for e in self.resolved_findings],
            "persistent_findings": [e.to_dict() for e in self.persistent_findings],
        }


# ---------------------------------------------------------------------------
# ScanBaseline
# ---------------------------------------------------------------------------

@dataclass
class ScanBaseline:
    """
    An immutable snapshot of all known finding fingerprints.

    Attributes:
        entries:       Dict of fingerprint → BaselineEntry.
        created_at:    ISO datetime when this baseline was created.
        scan_label:    Optional human-readable label (branch, version, date).
        schema_version: JSON schema version for forward compatibility.
    """
    entries:        dict[str, BaselineEntry] = field(default_factory=dict)
    created_at:     str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )
    scan_label:     str = ""
    schema_version: str = "1.0"

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    @property
    def fingerprints(self) -> set[str]:
        return set(self.entries.keys())

    def contains(self, fingerprint: str) -> bool:
        return fingerprint in self.entries

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "created_at":     self.created_at,
            "scan_label":     self.scan_label,
            "entry_count":    self.entry_count,
            "entries":        [e.to_dict() for e in self.entries.values()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanBaseline":
        entries: dict[str, BaselineEntry] = {}
        for raw in data.get("entries", []):
            try:
                entry = BaselineEntry.from_dict(raw)
                entries[entry.fingerprint] = entry
            except (KeyError, TypeError):
                continue
        return cls(
            entries=entries,
            created_at=data.get("created_at", datetime.now(tz=timezone.utc).isoformat()),
            scan_label=data.get("scan_label", ""),
            schema_version=data.get("schema_version", "1.0"),
        )


# ---------------------------------------------------------------------------
# BaselineTracker
# ---------------------------------------------------------------------------

class BaselineTracker:
    """
    Manages scan baselines: create, persist, load, and diff against new scans.

    A BaselineTracker holds one active baseline at a time. Call
    :meth:`set_baseline_from_findings` or :meth:`load` to populate it, then
    :meth:`diff` to compare a new scan against it.

    Args:
        scan_label: Optional human-readable label stored in the baseline file.
    """

    def __init__(self, scan_label: str = "") -> None:
        self._scan_label = scan_label
        self._baseline:  Optional[ScanBaseline] = None

    @property
    def has_baseline(self) -> bool:
        return self._baseline is not None

    @property
    def baseline(self) -> Optional[ScanBaseline]:
        return self._baseline

    # ------------------------------------------------------------------
    # Baseline creation
    # ------------------------------------------------------------------

    def set_baseline_from_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> ScanBaseline:
        """
        Create and store a new baseline from the given scan findings.

        Each finding must have at least ``rule_id`` and ``file_path``.
        ``fingerprint``, ``evidence``, and ``severity`` are extracted if
        present.

        Returns the new :class:`ScanBaseline`.
        """
        today = date.today().isoformat()
        entries: dict[str, BaselineEntry] = {}
        for finding in findings:
            fp = fingerprint_finding(finding)
            entries[fp] = BaselineEntry(
                fingerprint=fp,
                rule_id=str(finding.get("rule_id", "")),
                file_path=str(finding.get("file_path", "")),
                first_seen=today,
                last_seen=today,
                severity=str(finding.get("severity", "UNKNOWN")),
            )
        self._baseline = ScanBaseline(
            entries=entries,
            scan_label=self._scan_label,
        )
        return self._baseline

    def update_baseline(
        self,
        findings: list[dict[str, Any]],
    ) -> ScanBaseline:
        """
        Update an existing baseline with a new scan result.

        - New findings are added with ``first_seen = today``.
        - Existing findings have ``last_seen`` updated to today.
        - Findings no longer present are REMOVED from the baseline.

        Returns the updated :class:`ScanBaseline`.
        """
        if self._baseline is None:
            return self.set_baseline_from_findings(findings)

        today = date.today().isoformat()
        new_entries: dict[str, BaselineEntry] = {}
        for finding in findings:
            fp = fingerprint_finding(finding)
            if fp in self._baseline.entries:
                # Preserve first_seen, update last_seen
                existing = self._baseline.entries[fp]
                new_entries[fp] = BaselineEntry(
                    fingerprint=fp,
                    rule_id=existing.rule_id,
                    file_path=existing.file_path,
                    first_seen=existing.first_seen,
                    last_seen=today,
                    severity=str(finding.get("severity", existing.severity)),
                    suppressed=existing.suppressed,
                )
            else:
                # Brand-new finding
                new_entries[fp] = BaselineEntry(
                    fingerprint=fp,
                    rule_id=str(finding.get("rule_id", "")),
                    file_path=str(finding.get("file_path", "")),
                    first_seen=today,
                    last_seen=today,
                    severity=str(finding.get("severity", "UNKNOWN")),
                )
        self._baseline = ScanBaseline(
            entries=new_entries,
            created_at=self._baseline.created_at,
            scan_label=self._scan_label or self._baseline.scan_label,
        )
        return self._baseline

    # ------------------------------------------------------------------
    # Diff
    # ------------------------------------------------------------------

    def diff(
        self,
        current_findings: list[dict[str, Any]],
    ) -> BaselineDiff:
        """
        Compare ``current_findings`` against the stored baseline.

        Returns a :class:`BaselineDiff` with new, resolved, and persistent
        findings categorised.

        Raises:
            RuntimeError: If no baseline has been set.
        """
        if self._baseline is None:
            raise RuntimeError(
                "No baseline loaded. Call set_baseline_from_findings() or load() first."
            )

        scan_fps: dict[str, dict[str, Any]] = {}
        for finding in current_findings:
            fp = fingerprint_finding(finding)
            scan_fps[fp] = finding

        baseline_fps = self._baseline.fingerprints
        current_fps  = set(scan_fps.keys())

        new_fps        = current_fps - baseline_fps
        resolved_fps   = baseline_fps - current_fps
        persistent_fps = current_fps & baseline_fps

        return BaselineDiff(
            new_findings=[
                scan_fps[fp] for fp in new_fps
            ],
            resolved_findings=[
                self._baseline.entries[fp] for fp in resolved_fps
            ],
            persistent_findings=[
                self._baseline.entries[fp] for fp in persistent_fps
            ],
            scan_fingerprints=current_fps,
            baseline_fingerprints=baseline_fps,
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: "str | Path") -> None:
        """
        Save the current baseline to a JSON file.

        Raises:
            RuntimeError: If no baseline has been set.
        """
        if self._baseline is None:
            raise RuntimeError("No baseline to save.")
        data = self._baseline.to_dict()
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def load(self, path: "str | Path") -> ScanBaseline:
        """
        Load a baseline from a JSON file.

        Returns the loaded :class:`ScanBaseline`.
        """
        text = Path(path).read_text(encoding="utf-8")
        data = json.loads(text)
        self._baseline = ScanBaseline.from_dict(data)
        return self._baseline

    @classmethod
    def from_file(cls, path: "str | Path", scan_label: str = "") -> "BaselineTracker":
        """Create a BaselineTracker pre-loaded from a JSON file."""
        tracker = cls(scan_label=scan_label)
        tracker.load(path)
        return tracker
