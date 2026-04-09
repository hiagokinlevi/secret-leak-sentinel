"""
Entropy-Based Secret Scanner
================================
Detects potential secrets in text content using Shannon entropy analysis
combined with heuristic filters. High-entropy strings in specific character
sets (hex, base64, alphanumeric) that exceed configurable thresholds are
flagged as likely secrets.

Complements regex-based scanners by catching custom/obfuscated secrets
that don't match known patterns.

Check IDs
----------
ENT-001   High-entropy hex string (likely hash, key, or token)
ENT-002   High-entropy base64 string (likely encoded secret or key)
ENT-003   High-entropy alphanumeric string (likely API key or password)
ENT-004   High-entropy string adjacent to secret-related keyword

Usage::

    from scanners.entropy_scanner import EntropyScanner, EntropyFinding

    content = '''
    api_key = "aB3xK9mN2pQ7rT5vW8yZ1cD4fG6hJ0lE"
    db_pass = "hunter2"
    '''
    scanner = EntropyScanner()
    findings = scanner.scan_text(content, source_file="config.py")
    for f in findings:
        print(f.to_dict())
"""

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Entropy level enum
# ---------------------------------------------------------------------------

class EntropyLevel(Enum):
    """Named thresholds for Shannon entropy magnitude."""

    CRITICAL = 5.0  # >= 5.0 bits per character
    HIGH = 4.0      # >= 4.0 bits per character
    MEDIUM = 3.5    # >= 3.5 bits per character
    LOW = 3.0       # >= 3.0 bits per character


# ---------------------------------------------------------------------------
# Secret-adjacent keywords used by ENT-004
# ---------------------------------------------------------------------------

_SECRET_KEYWORDS: List[str] = [
    "key",
    "secret",
    "token",
    "password",
    "passwd",
    "pwd",
    "api",
    "auth",
    "credential",
    "private",
    "access",
    "bearer",
    "seed",
    "salt",
]


# ---------------------------------------------------------------------------
# Module-level helper functions
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Return the Shannon entropy (bits per character) of *s*.

    Uses the standard formula ``H = -sum(p * log2(p))`` where *p* is the
    probability of each distinct character.  Returns ``0.0`` for an empty
    string to avoid division-by-zero.
    """
    if not s:
        return 0.0
    length = len(s)
    # Build frequency table
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    # Compute entropy
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


def _is_hex_string(s: str) -> bool:
    """Return True if *s* is a valid high-entropy candidate in hex space.

    Conditions:
    - All characters are in ``[0-9a-fA-F]``
    - Length is at least 16 characters
    """
    if len(s) < 16:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))


def _is_base64_string(s: str) -> bool:
    """Return True if *s* looks like a base64-encoded value.

    Conditions:
    - All characters are in the base64 alphabet ``[A-Za-z0-9+/=]``
    - Length is at least 20 characters
    - Contains at least one uppercase AND one lowercase letter
      (rules out plain hex that happens to fit the alphabet)
    """
    if len(s) < 20:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        return False
    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    return has_upper and has_lower


def _is_alnum_string(s: str) -> bool:
    """Return True if *s* is a mixed-case alphanumeric secret candidate.

    Conditions:
    - All characters are in ``[A-Za-z0-9]``
    - Length is at least 16 characters
    - Contains at least one uppercase letter, one lowercase letter, and one
      digit (mixed character classes signal a deliberately constructed token)
    """
    if len(s) < 16:
        return False
    if not re.fullmatch(r"[A-Za-z0-9]+", s):
        return False
    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    has_digit = any(c.isdigit() for c in s)
    return has_upper and has_lower and has_digit


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class EntropyFinding:
    """A single high-entropy string identified as a potential secret.

    Attributes:
        check_id:     Rule identifier (ENT-001 … ENT-004).
        entropy:      Measured Shannon entropy of the flagged value.
        value:        Raw string that triggered the finding.
        masked_value: Partially redacted view safe for logging.
        source_file:  Path to the originating file (empty if scanned in memory).
        line_number:  1-based line number within the source.
        context:      Full text of the line containing the finding.
        keyword:      Secret-related keyword that co-triggered the finding
                      (populated for ENT-004; empty otherwise).
    """

    check_id: str
    entropy: float
    value: str
    masked_value: str
    source_file: str = ""
    line_number: int = 0
    context: str = ""
    keyword: str = ""

    # ------------------------------------------------------------------
    # Computed properties
    # ------------------------------------------------------------------

    @property
    def severity(self) -> str:
        """Return a human-readable severity label derived from entropy."""
        if self.entropy >= EntropyLevel.CRITICAL.value:
            return "CRITICAL"
        if self.entropy >= EntropyLevel.HIGH.value:
            return "HIGH"
        if self.entropy >= EntropyLevel.MEDIUM.value:
            return "MEDIUM"
        return "LOW"

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, object]:
        """Return a JSON-serialisable dictionary representation."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,  # derived property included explicitly
            "entropy": round(self.entropy, 4),
            "value": self.value,
            "masked_value": self.masked_value,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "context": self.context,
            "keyword": self.keyword,
        }

    def summary(self) -> str:
        """Return a one-line human-readable description of the finding."""
        loc = f"{self.source_file}:{self.line_number}" if self.source_file else f"line {self.line_number}"
        kw_part = f" (keyword: '{self.keyword}')" if self.keyword else ""
        return (
            f"[{self.check_id}] {self.severity} entropy={self.entropy:.3f} "
            f"value={self.masked_value} @ {loc}{kw_part}"
        )


@dataclass
class EntropyScanReport:
    """Aggregated results from scanning one or more text items.

    Attributes:
        findings:         All ``EntropyFinding`` objects produced by the scan.
        files_scanned:    Number of distinct source files (or logical items) processed.
        strings_analyzed: Total number of candidate strings evaluated.
        generated_at:     Unix timestamp when the report was created.
    """

    findings: List[EntropyFinding] = field(default_factory=list)
    files_scanned: int = 0
    strings_analyzed: int = 0
    generated_at: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Aggregate properties
    # ------------------------------------------------------------------

    @property
    def total_findings(self) -> int:
        """Total number of findings in this report."""
        return len(self.findings)

    @property
    def critical_findings(self) -> int:
        """Number of findings with CRITICAL severity."""
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_findings(self) -> int:
        """Number of findings with HIGH severity."""
        return sum(1 for f in self.findings if f.severity == "HIGH")

    # ------------------------------------------------------------------
    # Grouping helpers
    # ------------------------------------------------------------------

    def findings_by_check(self) -> Dict[str, List[EntropyFinding]]:
        """Return findings grouped by check_id."""
        result: Dict[str, List[EntropyFinding]] = {}
        for finding in self.findings:
            result.setdefault(finding.check_id, []).append(finding)
        return result

    def findings_by_file(self) -> Dict[str, List[EntropyFinding]]:
        """Return findings grouped by source_file."""
        result: Dict[str, List[EntropyFinding]] = {}
        for finding in self.findings:
            key = finding.source_file or "<unknown>"
            result.setdefault(key, []).append(finding)
        return result

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a multi-line summary string suitable for console output."""
        lines = [
            "Entropy Scan Report",
            "===================",
            f"Files scanned    : {self.files_scanned}",
            f"Strings analyzed : {self.strings_analyzed}",
            f"Total findings   : {self.total_findings}",
            f"  CRITICAL       : {self.critical_findings}",
            f"  HIGH           : {self.high_findings}",
            f"  MEDIUM         : {sum(1 for f in self.findings if f.severity == 'MEDIUM')}",
            f"  LOW            : {sum(1 for f in self.findings if f.severity == 'LOW')}",
        ]
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, object]:
        """Return a JSON-serialisable dictionary representation."""
        return {
            "generated_at": self.generated_at,
            "files_scanned": self.files_scanned,
            "strings_analyzed": self.strings_analyzed,
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class EntropyScanner:
    """Scan text for high-entropy strings that are likely to be secrets.

    Args:
        min_length:        Minimum token length to consider (default 16).
        max_length:        Maximum token length to consider (default 128).
        hex_threshold:     Minimum entropy to flag a hex string (ENT-001).
        base64_threshold:  Minimum entropy to flag a base64 string (ENT-002).
        alnum_threshold:   Minimum entropy to flag an alnum string (ENT-003).
        keyword_threshold: Minimum entropy to flag any string near a keyword (ENT-004).
    """

    def __init__(
        self,
        min_length: int = 16,
        max_length: int = 128,
        hex_threshold: float = 3.5,
        base64_threshold: float = 4.0,
        alnum_threshold: float = 3.8,
        keyword_threshold: float = 3.0,
    ) -> None:
        self.min_length = min_length
        self.max_length = max_length
        self.hex_threshold = hex_threshold
        self.base64_threshold = base64_threshold
        self.alnum_threshold = alnum_threshold
        self.keyword_threshold = keyword_threshold

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_masked(value: str) -> str:
        """Return a partially redacted version of *value* for safe logging."""
        if len(value) > 4:
            return value[:4] + "****"
        return "****"

    @staticmethod
    def _line_has_keyword(line: str) -> Optional[str]:
        """Return the first secret keyword found in *line* (case-insensitive), or None."""
        line_lower = line.lower()
        for kw in _SECRET_KEYWORDS:
            if kw in line_lower:
                return kw
        return None

    def _extract_candidates(self, line: str) -> List[str]:
        """Split *line* into non-numeric word tokens within the length window."""
        # Extract contiguous sequences of non-whitespace, non-quote, non-assign chars
        # that look like credential values (letters, digits, +, /, =, _, -, .)
        tokens = re.findall(r"[A-Za-z0-9+/=_\-\.]{" + str(self.min_length) + r",}", line)
        result: List[str] = []
        for tok in tokens:
            if len(tok) > self.max_length:
                # Slide a window — unlikely in practice but handled defensively
                for start in range(0, len(tok) - self.min_length + 1, self.min_length):
                    sub = tok[start : start + self.max_length]
                    if not sub.isdigit():
                        result.append(sub)
            else:
                if not tok.isdigit():
                    result.append(tok)
        return result

    # ------------------------------------------------------------------
    # Public scanning API
    # ------------------------------------------------------------------

    def scan_text(
        self,
        content: str,
        source_file: str = "",
    ) -> List[EntropyFinding]:
        """Scan *content* for high-entropy secret candidates.

        Args:
            content:     Raw text to scan (multi-line strings accepted).
            source_file: Optional label used in findings (e.g. a file path).

        Returns:
            Deduplicated list of :class:`EntropyFinding` objects.
        """
        findings: List[EntropyFinding] = []
        # Track (value, check_id, line_number) tuples to deduplicate
        seen: set = set()

        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            candidates = self._extract_candidates(line)
            keyword_on_line = self._line_has_keyword(line)

            for candidate in candidates:
                entropy = _shannon_entropy(candidate)

                def _emit(check_id: str, kw: str = "") -> None:
                    """Append a finding if not already seen."""
                    key = (candidate, check_id, lineno)
                    if key in seen:
                        return
                    seen.add(key)
                    findings.append(
                        EntropyFinding(
                            check_id=check_id,
                            entropy=entropy,
                            value=candidate,
                            masked_value=self._make_masked(candidate),
                            source_file=source_file,
                            line_number=lineno,
                            context=line.strip(),
                            keyword=kw,
                        )
                    )

                # ENT-001: high-entropy hex string
                if _is_hex_string(candidate) and entropy >= self.hex_threshold:
                    _emit("ENT-001")

                # ENT-002: high-entropy base64 string
                if _is_base64_string(candidate) and entropy >= self.base64_threshold:
                    _emit("ENT-002")

                # ENT-003: high-entropy alphanumeric string
                if _is_alnum_string(candidate) and entropy >= self.alnum_threshold:
                    _emit("ENT-003")

                # ENT-004: any high-entropy string near a secret keyword
                # Fires regardless of ENT-001/002/003 — they can co-fire
                if keyword_on_line and entropy >= self.keyword_threshold:
                    _emit("ENT-004", kw=keyword_on_line)

        return findings

    def scan_file(self, file_path: str) -> List[EntropyFinding]:
        """Read *file_path* and scan its contents.

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of :class:`EntropyFinding` objects (may be empty).

        Raises:
            OSError: If the file cannot be opened.
        """
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        return self.scan_text(content, source_file=file_path)

    def scan_texts(
        self,
        items: List[Dict[str, str]],
    ) -> EntropyScanReport:
        """Scan multiple text items and return an aggregated report.

        Each item in *items* must contain a ``"content"`` key and may
        optionally include a ``"source_file"`` key.

        Args:
            items: List of dicts with ``"content"`` (required) and
                   ``"source_file"`` (optional) keys.

        Returns:
            :class:`EntropyScanReport` summarising all findings.
        """
        all_findings: List[EntropyFinding] = []
        strings_analyzed = 0

        for item in items:
            content = item.get("content", "")
            source_file = item.get("source_file", "")
            # Count candidates across all lines for the report metric
            for line in content.splitlines():
                strings_analyzed += len(self._extract_candidates(line))
            item_findings = self.scan_text(content, source_file=source_file)
            all_findings.extend(item_findings)

        return EntropyScanReport(
            findings=all_findings,
            files_scanned=len(items),
            strings_analyzed=strings_analyzed,
        )
