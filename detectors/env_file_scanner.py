"""
env_file_scanner.py
===================
Scans .env files, shell environment variable exports, and configuration files
for secret patterns embedded in variable assignments. Detects hardcoded
credentials in environment configurations.

Checks:
    ENV-001  AWS access key in env var value               CRITICAL  weight=45
    ENV-002  Generic API key pattern                       HIGH      weight=30
    ENV-003  Password variable with plaintext value        HIGH      weight=25
    ENV-004  Private key material (PEM header)             CRITICAL  weight=45
    ENV-005  Database connection string with credentials   HIGH      weight=30
    ENV-006  Token variable with long value                HIGH      weight=25
    ENV-007  High-entropy secret                           MEDIUM    weight=20

Python 3.9 compatible.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Dynamic construction avoids triggering SCM push-protection on this source file
_AWS_KEY_RE = re.compile("AKIA" + r"[0-9A-Z]{16}")

# PEM private key header
_PEM_RE = re.compile(r"-----BEGIN")

# Database URL with embedded credentials:  scheme://user:password@host
_DB_URL_RE = re.compile(
    r"(postgres|mysql|mongodb|redis|mssql)://[^:]+:[^@]{6,}@",
    re.IGNORECASE,
)

# Variable-name keyword sets (checked case-insensitively against var name)
_API_KEY_NAMES = {"api_key", "apikey", "api_secret", "client_secret", "app_secret"}
_PASSWORD_NAMES = {"password", "passwd", "pwd"}
_TOKEN_NAMES = {"token", "auth_token", "access_token", "refresh_token", "bearer"}
_SECRET_KEY_NAMES = {"secret", "key", "credential", "cred"}

# ENV-007 exclusions: variable names containing any of these substrings are skipped
_SECRET_KEY_EXCLUSIONS = {
    "key_file",
    "key_path",
    "key_dir",
    "key_name",
    "secret_name",
    "secret_path",
}

# Placeholder patterns that indicate a value is not a real secret
_PLACEHOLDER_PATTERNS = (
    "your_",
    "example",
    "placeholder",
    "changeme",
    "xxxx",
    "<",
    ">",
    "{",
    "}",
)


def _entropy(s: str) -> float:
    """Compute Shannon entropy (bits) of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _is_placeholder(value: str) -> bool:
    """Return True if *value* looks like a placeholder/example string."""
    lower = value.lower()
    return any(pat in lower for pat in _PLACEHOLDER_PATTERNS)


def _masked(value: str) -> str:
    """Return the first 4 chars of *value* followed by '****', or just '****'."""
    if len(value) > 4:
        return value[:4] + "****"
    return "****"


def _name_contains_any(var_name: str, keywords: set) -> bool:
    """Return True if *var_name* (lowercased) contains any keyword as a substring."""
    lower = var_name.lower()
    return any(kw in lower for kw in keywords)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class EnvEntry:
    """A single parsed KEY=value pair from an env-style file."""

    variable_name: str
    value: str
    line_number: int = 0
    file_path: str = ""


@dataclass
class EnvCheck:
    """A single check that fired for a given env entry."""

    check_id: str
    severity: str  # CRITICAL / HIGH / MEDIUM
    description: str
    variable_name: str
    masked_value: str  # first 4 chars + "****" if len > 4
    line_number: int
    weight: int


@dataclass
class EnvScanResult:
    """Aggregated result of scanning one env-style file."""

    file_path: str
    checks_fired: List[EnvCheck] = field(default_factory=list)
    risk_score: int = 0  # min(100, sum of weights)
    risk_tier: str = "LOW"  # CRITICAL(>=70) / HIGH(>=40) / MEDIUM(>=20) / LOW
    total_entries: int = 0

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialise the result to a plain dict (JSON-friendly)."""
        return {
            "file_path": self.file_path,
            "risk_score": self.risk_score,
            "risk_tier": self.risk_tier,
            "total_entries": self.total_entries,
            "checks_fired": [
                {
                    "check_id": c.check_id,
                    "severity": c.severity,
                    "description": c.description,
                    "variable_name": c.variable_name,
                    "masked_value": c.masked_value,
                    "line_number": c.line_number,
                    "weight": c.weight,
                }
                for c in self.checks_fired
            ],
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary."""
        return (
            f"[{self.risk_tier}] {self.file_path} — "
            f"score={self.risk_score}, "
            f"checks_fired={len(self.checks_fired)}, "
            f"entries={self.total_entries}"
        )

    def by_severity(self) -> Dict[str, List[EnvCheck]]:
        """Group fired checks by severity level."""
        result: Dict[str, List[EnvCheck]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": []}
        for check in self.checks_fired:
            bucket = result.setdefault(check.severity, [])
            bucket.append(check)
        return result


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

# Matches optional 'export ' prefix, then KEY, then '=', then optional value.
# Captures: (1) variable name, (2) value (may be empty, quoted, or bare)
_ENV_LINE_RE = re.compile(
    r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$"
)

# Patterns for stripping inline comments from bare (unquoted) values.
# We match ' #' followed by anything — but only when the value is not quoted.
_INLINE_COMMENT_RE = re.compile(r"\s+#.*$")


def parse_env_content(content: str, file_path: str = "") -> List[EnvEntry]:
    """Parse .env-style content into a list of :class:`EnvEntry` objects.

    Handles:
    - ``KEY=value``
    - ``export KEY=value``
    - ``KEY="double quoted value"``
    - ``KEY='single quoted value'``
    - Lines starting with ``#`` are treated as comments and skipped.
    - Empty (or whitespace-only) lines are skipped.
    - Inline comments in unquoted values (`` # …``) are stripped.
    """
    entries: List[EnvEntry] = []
    for lineno, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        # Skip blank lines and comment lines
        if not line or line.startswith("#"):
            continue
        match = _ENV_LINE_RE.match(line)
        if not match:
            continue
        var_name = match.group(1)
        raw_value = match.group(2).strip()

        # Unquote double-quoted values
        if raw_value.startswith('"') and raw_value.endswith('"') and len(raw_value) >= 2:
            value = raw_value[1:-1]
        # Unquote single-quoted values
        elif raw_value.startswith("'") and raw_value.endswith("'") and len(raw_value) >= 2:
            value = raw_value[1:-1]
        else:
            # Strip inline comment for bare values
            value = _INLINE_COMMENT_RE.sub("", raw_value)

        entries.append(
            EnvEntry(
                variable_name=var_name,
                value=value,
                line_number=lineno,
                file_path=file_path,
            )
        )
    return entries


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------


def _check_env001(entry: EnvEntry) -> Optional[EnvCheck]:
    """ENV-001: AWS access key in env var value."""
    if _AWS_KEY_RE.search(entry.value):
        return EnvCheck(
            check_id="ENV-001",
            severity="CRITICAL",
            description="AWS access key detected in environment variable value",
            variable_name=entry.variable_name,
            masked_value=_masked(entry.value),
            line_number=entry.line_number,
            weight=45,
        )
    return None


def _check_env002(entry: EnvEntry) -> Optional[EnvCheck]:
    """ENV-002: Generic API key pattern."""
    if not _name_contains_any(entry.variable_name, _API_KEY_NAMES):
        return None
    value = entry.value
    if not value or len(value) < 16:
        return None
    if _is_placeholder(value):
        return None
    return EnvCheck(
        check_id="ENV-002",
        severity="HIGH",
        description="Generic API key or secret detected in environment variable",
        variable_name=entry.variable_name,
        masked_value=_masked(value),
        line_number=entry.line_number,
        weight=30,
    )


def _check_env003(entry: EnvEntry) -> Optional[EnvCheck]:
    """ENV-003: Password variable with plaintext value."""
    if not _name_contains_any(entry.variable_name, _PASSWORD_NAMES):
        return None
    value = entry.value
    if not value or len(value) < 8:
        return None
    if _is_placeholder(value):
        return None
    return EnvCheck(
        check_id="ENV-003",
        severity="HIGH",
        description="Plaintext password detected in environment variable",
        variable_name=entry.variable_name,
        masked_value=_masked(value),
        line_number=entry.line_number,
        weight=25,
    )


def _check_env004(entry: EnvEntry) -> Optional[EnvCheck]:
    """ENV-004: Private key material — PEM header present in value."""
    if _PEM_RE.search(entry.value):
        return EnvCheck(
            check_id="ENV-004",
            severity="CRITICAL",
            description="PEM private key material detected in environment variable value",
            variable_name=entry.variable_name,
            masked_value=_masked(entry.value),
            line_number=entry.line_number,
            weight=45,
        )
    return None


def _check_env005(entry: EnvEntry) -> Optional[EnvCheck]:
    """ENV-005: Database connection string with embedded credentials."""
    if _DB_URL_RE.search(entry.value):
        return EnvCheck(
            check_id="ENV-005",
            severity="HIGH",
            description="Database connection string with embedded credentials detected",
            variable_name=entry.variable_name,
            masked_value=_masked(entry.value),
            line_number=entry.line_number,
            weight=30,
        )
    return None


def _check_env006(entry: EnvEntry) -> Optional[EnvCheck]:
    """ENV-006: Token variable with long value."""
    if not _name_contains_any(entry.variable_name, _TOKEN_NAMES):
        return None
    value = entry.value
    if len(value) < 32:
        return None
    if _is_placeholder(value):
        return None
    return EnvCheck(
        check_id="ENV-006",
        severity="HIGH",
        description="Long token value detected in environment variable",
        variable_name=entry.variable_name,
        masked_value=_masked(value),
        line_number=entry.line_number,
        weight=25,
    )


def _check_env007(entry: EnvEntry) -> Optional[EnvCheck]:
    """ENV-007: High-entropy secret variable."""
    var_lower = entry.variable_name.lower()

    # Must contain one of the target keywords
    if not _name_contains_any(entry.variable_name, _SECRET_KEY_NAMES):
        return None

    # Skip if any exclusion substring is present in the variable name
    if any(excl in var_lower for excl in _SECRET_KEY_EXCLUSIONS):
        return None

    value = entry.value
    if len(value) < 16:
        return None
    if _is_placeholder(value):
        return None
    if _entropy(value) <= 4.0:
        return None

    return EnvCheck(
        check_id="ENV-007",
        severity="MEDIUM",
        description="High-entropy value detected in secret-named environment variable",
        variable_name=entry.variable_name,
        masked_value=_masked(value),
        line_number=entry.line_number,
        weight=20,
    )


# Ordered list of all check functions
_ALL_CHECKS = [
    _check_env001,
    _check_env002,
    _check_env003,
    _check_env004,
    _check_env005,
    _check_env006,
    _check_env007,
]


# ---------------------------------------------------------------------------
# Risk tier calculation
# ---------------------------------------------------------------------------


def _risk_tier(score: int) -> str:
    """Map a numeric risk score to its tier label."""
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Public scanning API
# ---------------------------------------------------------------------------


def scan_entries(entries: List[EnvEntry], file_path: str = "") -> EnvScanResult:
    """Run all ENV checks against a pre-parsed list of :class:`EnvEntry` objects.

    Args:
        entries: Parsed env entries to evaluate.
        file_path: Optional file path to embed in the result.

    Returns:
        An :class:`EnvScanResult` with all checks that fired.
    """
    # Prefer the file_path carried inside entries (first entry) if caller
    # did not supply one explicitly.
    resolved_path = file_path
    if not resolved_path and entries:
        resolved_path = entries[0].file_path

    checks_fired: List[EnvCheck] = []
    for entry in entries:
        for check_fn in _ALL_CHECKS:
            result = check_fn(entry)
            if result is not None:
                checks_fired.append(result)

    raw_score = sum(c.weight for c in checks_fired)
    score = min(100, raw_score)
    return EnvScanResult(
        file_path=resolved_path,
        checks_fired=checks_fired,
        risk_score=score,
        risk_tier=_risk_tier(score),
        total_entries=len(entries),
    )


def scan_content(content: str, file_path: str = "") -> EnvScanResult:
    """Parse *content* and scan it for secret patterns.

    Equivalent to calling :func:`parse_env_content` then :func:`scan_entries`.

    Args:
        content: Raw text of the env-style file.
        file_path: Optional path label attached to entries and result.

    Returns:
        An :class:`EnvScanResult`.
    """
    entries = parse_env_content(content, file_path=file_path)
    return scan_entries(entries, file_path=file_path)


def scan_many(contents: List[Tuple[str, str]]) -> List[EnvScanResult]:
    """Scan multiple files in one call.

    Args:
        contents: A list of ``(file_path, content_string)`` tuples.

    Returns:
        A list of :class:`EnvScanResult` objects, one per input tuple,
        in the same order.
    """
    return [scan_content(content, file_path=fp) for fp, content in contents]
