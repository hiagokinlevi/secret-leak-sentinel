"""
Secret Leak Suppression Governance
=====================================
Structured false-positive suppression system for secret detection findings.

When a secret detector flags a finding that is a known false positive (e.g.
a test fixture, an example key in documentation, or a base64-encoded non-secret),
teams need a governed way to suppress it with: a reason, an expiry date, an owner,
and an audit trail.

This module provides:
  - SuppressionRule: A structured suppression entry tied to a specific finding.
  - SuppressionStore: In-memory and file-backed registry of active suppressions.
  - is_suppressed(): Check if a given finding is covered by an active suppression.
  - audit_suppressions(): Report on expired, near-expiry, and permanently suppressed items.

Suppression Matching:
  A finding is suppressed when ALL of the following match:
    - file_path:    exact match or fnmatch glob (e.g. "tests/**")
    - rule_id:      exact match or "*" to suppress all rules for this path
    - fingerprint:  optional SHA-256 of the finding for exact suppression
                    (recommended over broad glob suppression)

IMPORTANT GOVERNANCE NOTES:
  - Suppressions should NEVER be permanent without a documented reason.
  - Suppressions should be reviewed regularly (use audit_suppressions()).
  - Add suppression rules to version control and require PR review.
  - Never suppress CRITICAL findings without security team approval.

Usage:
    from detectors.suppression import SuppressionRule, SuppressionStore

    store = SuppressionStore()
    store.add(SuppressionRule(
        rule_id="REGEX-001",
        file_path="tests/fixtures/test_data.py",
        reason="Test fixture key — not a real secret",
        owner="security@example.com",
        expires="2026-12-31",
    ))

    finding = {"rule_id": "REGEX-001", "file_path": "tests/fixtures/test_data.py"}
    if store.is_suppressed(finding):
        print("Finding suppressed — skipping")
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SuppressionRule:
    """
    A suppression rule for a secret detection finding.

    A finding is suppressed when:
      - its rule_id matches this rule's rule_id (or rule_id is "*")
      - its file_path matches this rule's file_path (exact or glob)
      - if fingerprint is set, the finding's fingerprint matches

    Attributes:
        rule_id:      Detector rule ID to suppress (e.g. "REGEX-001"), or "*" for all.
        file_path:    Exact path or glob pattern (e.g. "tests/**/*.py").
        reason:       Required — why this suppression is justified.
        owner:        Email or team responsible for this suppression.
        expires:      ISO date "YYYY-MM-DD" after which the suppression is invalid.
                      None means the suppression never expires (strongly discouraged).
        fingerprint:  Optional SHA-256 of the finding evidence for precise matching.
        created_at:   ISO date when this rule was created.
        suppression_id: Auto-generated stable identifier.
    """
    rule_id:         str
    file_path:       str
    reason:          str
    owner:           str = "unknown"
    expires:         Optional[str] = None
    fingerprint:     Optional[str] = None
    created_at:      str = field(
        default_factory=lambda: date.today().isoformat()
    )
    suppression_id:  str = ""

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError("SuppressionRule.reason must not be empty")
        # Auto-generate suppression_id from rule content
        if not self.suppression_id:
            parts = f"{self.rule_id}:{self.file_path}:{self.fingerprint or ''}"
            self.suppression_id = hashlib.sha256(parts.encode()).hexdigest()[:16]

    @property
    def is_expired(self) -> bool:
        """Return True if this rule's expiry date has passed."""
        if self.expires is None:
            return False
        try:
            return date.fromisoformat(self.expires) < date.today()
        except ValueError:
            return False

    @property
    def days_until_expiry(self) -> Optional[int]:
        """Return days until expiry, None if no expiry set, negative if already expired."""
        if self.expires is None:
            return None
        try:
            expiry = date.fromisoformat(self.expires)
            return (expiry - date.today()).days
        except ValueError:
            return None

    @property
    def is_permanent(self) -> bool:
        """Return True if this suppression has no expiry date."""
        return self.expires is None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SuppressionRule":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Audit report
# ---------------------------------------------------------------------------

@dataclass
class SuppressionAuditReport:
    """Report on the state of all suppressions in a store."""
    total:           int = 0
    active:          int = 0
    expired:         int = 0
    permanent:       int = 0
    expiring_soon:   int = 0          # within 30 days
    expired_rules:   list[SuppressionRule] = field(default_factory=list)
    permanent_rules: list[SuppressionRule] = field(default_factory=list)
    soon_expiring_rules: list[SuppressionRule] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"Suppression audit: {self.total} total | "
            f"{self.active} active | {self.expired} expired | "
            f"{self.permanent} permanent (no expiry) | "
            f"{self.expiring_soon} expiring within 30 days"
        )


# ---------------------------------------------------------------------------
# SuppressionStore
# ---------------------------------------------------------------------------

class SuppressionStore:
    """
    Registry of active suppression rules.

    Supports:
      - In-memory operation (default)
      - JSON file persistence (load_json / save_json)
      - Finding lookup (is_suppressed)
      - Expiry management (expire_stale, audit_suppressions)

    Thread safety: Not thread-safe. Add external locking for concurrent use.
    """

    def __init__(self) -> None:
        self._rules: dict[str, SuppressionRule] = {}   # suppression_id → rule

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add(self, rule: SuppressionRule) -> None:
        """Add or replace a suppression rule."""
        self._rules[rule.suppression_id] = rule

    def remove(self, suppression_id: str) -> bool:
        """Remove a suppression rule by ID. Returns True if it existed."""
        return self._rules.pop(suppression_id, None) is not None

    def get(self, suppression_id: str) -> Optional[SuppressionRule]:
        """Return a suppression rule by ID."""
        return self._rules.get(suppression_id)

    def all_rules(self) -> list[SuppressionRule]:
        """Return all registered rules."""
        return list(self._rules.values())

    def active_rules(self) -> list[SuppressionRule]:
        """Return only non-expired rules."""
        return [r for r in self._rules.values() if not r.is_expired]

    @property
    def count(self) -> int:
        return len(self._rules)

    # ------------------------------------------------------------------
    # Suppression check
    # ------------------------------------------------------------------

    def is_suppressed(self, finding: dict[str, Any]) -> Optional[SuppressionRule]:
        """
        Check if a finding is covered by an active suppression rule.

        Args:
            finding: Dict with at minimum:
                     - "rule_id":     detector rule ID (e.g. "REGEX-001")
                     - "file_path":   file path where the finding was detected
                     - "fingerprint": optional SHA-256 of the finding evidence

        Returns:
            The matching SuppressionRule if suppressed, else None.
        """
        finding_rule_id    = str(finding.get("rule_id", ""))
        finding_path       = str(finding.get("file_path", ""))
        finding_fingerprint = finding.get("fingerprint") or finding.get("evidence_hash")

        for rule in self._rules.values():
            # Skip expired rules
            if rule.is_expired:
                continue

            # Match rule_id (exact or wildcard)
            if rule.rule_id != "*" and rule.rule_id != finding_rule_id:
                continue

            # Match file_path (exact or fnmatch glob)
            if not fnmatch.fnmatch(finding_path, rule.file_path):
                continue

            # Match fingerprint (if rule has one, it must match)
            if rule.fingerprint is not None:
                if str(finding_fingerprint) != rule.fingerprint:
                    continue

            return rule

        return None

    def filter_suppressed(
        self, findings: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """
        Split findings into (active, suppressed) lists.

        Args:
            findings: List of finding dicts.

        Returns:
            Tuple of (active_findings, suppressed_findings).
        """
        active = []
        suppressed = []
        for finding in findings:
            if self.is_suppressed(finding):
                suppressed.append(finding)
            else:
                active.append(finding)
        return active, suppressed

    # ------------------------------------------------------------------
    # Expiry management
    # ------------------------------------------------------------------

    def expire_stale(self) -> list[SuppressionRule]:
        """
        Remove expired suppression rules.

        Returns the list of removed rules (for audit logging).
        """
        expired = [r for r in self._rules.values() if r.is_expired]
        for rule in expired:
            del self._rules[rule.suppression_id]
        return expired

    def audit_suppressions(self, expiry_warning_days: int = 30) -> SuppressionAuditReport:
        """
        Produce an audit report on all suppression rules.

        Args:
            expiry_warning_days: Rules expiring within this many days are flagged.

        Returns:
            SuppressionAuditReport with counts and lists of notable rules.
        """
        report = SuppressionAuditReport(total=len(self._rules))
        for rule in self._rules.values():
            if rule.is_expired:
                report.expired += 1
                report.expired_rules.append(rule)
            elif rule.is_permanent:
                report.permanent += 1
                report.permanent_rules.append(rule)
            else:
                report.active += 1
                days = rule.days_until_expiry
                if days is not None and 0 <= days <= expiry_warning_days:
                    report.expiring_soon += 1
                    report.soon_expiring_rules.append(rule)
        return report

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_json(self, path: "str | Path") -> None:
        """
        Save all suppression rules to a JSON file.

        The file can be committed to version control for team-wide suppression governance.

        Args:
            path: File path to write to.
        """
        data = {
            "schema_version": "1.0",
            "saved_at": datetime.now(tz=timezone.utc).isoformat(),
            "rules": [r.to_dict() for r in self._rules.values()],
        }
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def load_json(self, path: "str | Path") -> int:
        """
        Load suppression rules from a JSON file.

        Merges with any already-registered rules (existing rules with the same
        suppression_id are overwritten by the loaded ones).

        Args:
            path: File path to read from.

        Returns:
            Number of rules loaded.
        """
        text = Path(path).read_text(encoding="utf-8")
        data = json.loads(text)
        rules_data = data.get("rules", [])
        count = 0
        for rule_dict in rules_data:
            try:
                rule = SuppressionRule.from_dict(rule_dict)
                self._rules[rule.suppression_id] = rule
                count += 1
            except (TypeError, ValueError):
                continue
        return count

    @classmethod
    def from_json(cls, path: "str | Path") -> "SuppressionStore":
        """Create a SuppressionStore pre-loaded from a JSON file."""
        store = cls()
        store.load_json(path)
        return store


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def make_fingerprint(evidence: str) -> str:
    """
    Generate a SHA-256 fingerprint for a piece of finding evidence.

    Use this when creating SuppressionRules with fingerprint= for precise matching.

    Args:
        evidence: The finding evidence string (e.g. the masked token value + file + line).

    Returns:
        Hex SHA-256 string (64 characters).
    """
    return hashlib.sha256(evidence.encode("utf-8")).hexdigest()
