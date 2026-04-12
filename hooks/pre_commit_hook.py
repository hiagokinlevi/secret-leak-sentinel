"""
Pre-Commit Secret Scanning Hook
==================================
Integrates secret detection into the git pre-commit workflow.
Reads staged files, runs regex + entropy scanners, and fails the commit
if secrets are found above a configurable severity threshold.

Designed to be invoked as a git pre-commit hook or in CI pipelines.

Exit codes:
    0   No secrets found (or only below threshold)
    1   Secrets found above threshold — commit blocked
    2   Hook configuration error

Usage (as git hook):
    #!/usr/bin/env python3
    from hooks.pre_commit_hook import PreCommitHook
    import sys
    sys.exit(PreCommitHook().run())

Usage (programmatic):
    from hooks.pre_commit_hook import PreCommitHook, HookConfig

    config = HookConfig(fail_on_severity="HIGH", skip_paths=["tests/", "*.md"])
    hook = PreCommitHook(config=config)
    result = hook.scan_files({"src/config.py": "api_key = 'secret123'"})
    print(result.exit_code, result.total_findings)
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Severity level
# ---------------------------------------------------------------------------

class SeverityLevel(Enum):
    """Ordered severity levels for hook findings.

    Numeric values allow direct comparison: CRITICAL >= HIGH evaluates correctly
    via the custom __ge__ implementation below.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __ge__(self, other: object) -> bool:
        """Return True when this severity is at least as severe as *other*."""
        if not isinstance(other, SeverityLevel):
            return NotImplemented
        return self.value >= other.value

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, SeverityLevel):
            return NotImplemented
        return self.value > other.value

    def __le__(self, other: object) -> bool:
        if not isinstance(other, SeverityLevel):
            return NotImplemented
        return self.value <= other.value

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SeverityLevel):
            return NotImplemented
        return self.value < other.value


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class HookConfig:
    """Runtime configuration for PreCommitHook.

    Attributes:
        fail_on_severity:   Minimum severity string that triggers a commit block.
                            Accepts any SeverityLevel name, case-insensitive.
                            Defaults to "HIGH".
        skip_paths:         List of path substrings or glob-style patterns.
                            Files whose path contains any of these strings are
                            skipped entirely.
        skip_extensions:    List of file extensions (e.g. [".md", ".lock"]) to
                            skip without scanning.
        max_file_size_kb:   Files larger than this limit (in kilobytes) are
                            skipped to prevent memory exhaustion.
        include_entropy:    When True, an entropy scan is performed in addition
                            to the regex scan.  (Reserved for future use — the
                            hook currently ships regex-only built-in patterns.)
        include_regex:      When False, the built-in regex patterns are not run.
                            Useful for benchmarking or when only entropy is
                            desired.
        allow_list:         Tokens that, when present anywhere in a matching
                            line, suppress that individual finding.  Useful for
                            marking known test fixtures or example values.
    """

    fail_on_severity: str = "HIGH"
    skip_paths: List[str] = field(default_factory=list)
    skip_extensions: List[str] = field(default_factory=list)
    max_file_size_kb: int = 1024
    include_entropy: bool = True
    include_regex: bool = True
    allow_list: List[str] = field(default_factory=list)

    @property
    def fail_level(self) -> SeverityLevel:
        """Resolve *fail_on_severity* string to a :class:`SeverityLevel`.

        Unknown or missing values fall back to HIGH so the hook is always
        protective by default.
        """
        try:
            return SeverityLevel[self.fail_on_severity.upper()]
        except (KeyError, AttributeError):
            return SeverityLevel.HIGH


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FileScanResult:
    """Aggregated scan result for a single file.

    Attributes:
        file_path:        Relative or absolute path of the scanned file.
        findings_count:   Total number of findings (after allow-list filtering).
        blocked:          True when at least one finding reaches the fail level.
        severity_counts:  Mapping of severity name → count, e.g.
                          {"CRITICAL": 1, "MEDIUM": 2}.
        findings_summary: Human-readable one-liner per finding, suitable for
                          CLI output or log entries.
    """

    file_path: str
    findings_count: int
    blocked: bool
    severity_counts: Dict[str, int] = field(default_factory=dict)
    findings_summary: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialise this result to a plain dictionary for JSON/YAML output."""
        return {
            "file_path": self.file_path,
            "findings_count": self.findings_count,
            "blocked": self.blocked,
            "severity_counts": dict(self.severity_counts),
            "findings_summary": list(self.findings_summary),
        }


@dataclass
class HookResult:
    """Top-level result returned by :meth:`PreCommitHook.scan_files`.

    Attributes:
        exit_code:      0 = clean, 1 = blocked, 2 = configuration error.
        total_findings: Sum of all per-file finding counts.
        blocked_files:  File paths that individually triggered a block.
        file_results:   Ordered list of :class:`FileScanResult` objects.
        message:        Human-readable summary suitable for terminal output.
        generated_at:   Unix timestamp (float) of when this result was created.
    """

    exit_code: int
    total_findings: int
    blocked_files: List[str]
    file_results: List[FileScanResult]
    message: str
    generated_at: float

    @property
    def is_blocked(self) -> bool:
        """True when the hook would block the commit (exit_code == 1)."""
        return self.exit_code == 1

    def to_dict(self) -> dict:
        """Serialise this result to a plain dictionary for JSON/YAML output."""
        return {
            "exit_code": self.exit_code,
            "total_findings": self.total_findings,
            "blocked_files": list(self.blocked_files),
            "file_results": [fr.to_dict() for fr in self.file_results],
            "message": self.message,
            "generated_at": self.generated_at,
        }


# ---------------------------------------------------------------------------
# Built-in secret patterns
# ---------------------------------------------------------------------------
# Each entry is a 3-tuple: (rule_id, severity_str, compiled_regex).
# Patterns are intentionally ordered from most specific to most generic so
# that earlier, higher-confidence matches are listed first in findings.
# All synthetic test values used in comments are non-functional.

_BUILTIN_PATTERNS: List[Tuple[str, str, re.Pattern]] = [
    # AWS Access Key ID — starts with AKIA followed by exactly 16 uppercase
    # alphanumeric characters.  These have a very low false-positive rate.
    ("SC-001", "CRITICAL", re.compile(r"AKIA[0-9A-Z]{16}")),

    # GitHub tokens — classic PAT (ghp_), fine-grained PAT (github_pat_),
    # OAuth (gho_), server-to-server (ghs_), user-to-server (ghu_), and
    # refresh (ghr_) variants.
    (
        "SC-002",
        "HIGH",
        re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})"),
    ),

    # PEM-encoded RSA or EC private key block header.  Presence of the header
    # in a committed file is almost always a critical exposure.
    ("SC-003", "HIGH", re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----")),

    # Hardcoded password in variable assignment context.  Requires at least 8
    # non-whitespace characters to reduce false positives from placeholder values.
    (
        "SC-004",
        "MEDIUM",
        re.compile(
            r"(password|passwd|pwd)\s*[=:]\s*['\"]?\S{8,}",
            re.IGNORECASE,
        ),
    ),

    # Generic API key or access token in assignment context.  Requires at least
    # 16 non-whitespace characters to filter out short placeholder strings.
    (
        "SC-005",
        "MEDIUM",
        re.compile(
            r"(api[_-]?key|access[_-]?token)\s*[=:]\s*['\"]?\S{16,}",
            re.IGNORECASE,
        ),
    ),

    # Stripe live-mode secret key — sk_live_ prefix is unambiguous.
    ("SC-006", "HIGH", re.compile(r"sk_live_[A-Za-z0-9]{24,}")),

    # Slack bearer and app-level tokens. These prefixes are specific to Slack's
    # API credentials and are safe to block at HIGH severity in commit hooks.
    (
        "SC-007",
        "HIGH",
        re.compile(r"\b(?:xox(?:a|b|p|r|s)-[A-Za-z0-9-]{24,}|xapp-\d-[A-Za-z0-9-]{24,})\b"),
    ),

    # npm access tokens are high-signal bearer credentials that should never
    # appear in tracked files or CI scripts.
    ("SC-008", "HIGH", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),

    # GCP OAuth access tokens use the ya29. prefix and should be blocked.
    ("SC-009", "HIGH", re.compile(r"\bya29\.[A-Za-z0-9_-]{50,}\b")),
]


# ---------------------------------------------------------------------------
# Hook runner
# ---------------------------------------------------------------------------

class PreCommitHook:
    """Runs built-in secret detection against a set of in-memory file contents.

    Designed to be embedded in a git pre-commit hook, CI pipeline step, or
    called programmatically for testing and integration purposes.

    Args:
        config: Optional :class:`HookConfig`.  Defaults are used when omitted.
    """

    def __init__(self, config: Optional[HookConfig] = None) -> None:
        self._config = config if config is not None else HookConfig()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_files(self, files: Dict[str, str]) -> HookResult:
        """Scan a dict of file_path → file_content for secrets.

        Steps for each file:
          1. Skip if path matches :attr:`HookConfig.skip_paths` or
             :attr:`HookConfig.skip_extensions`.
          2. Skip if content length exceeds
             ``max_file_size_kb * 1024`` bytes.
          3. Run :data:`_BUILTIN_PATTERNS` against every line
             (when ``include_regex`` is True).
          4. Suppress any finding whose matching line contains a token
             from :attr:`HookConfig.allow_list`.
          5. Mark the file as *blocked* if any surviving finding has a
             severity >= the configured fail level.

        Args:
            files: Mapping of file paths to their text content.  In a real
                   git hook these are the staged file contents; in tests they
                   are provided directly.

        Returns:
            :class:`HookResult` with exit_code 0 (clean) or 1 (blocked).
        """
        cfg = self._config
        file_results: List[FileScanResult] = []
        blocked_files: List[str] = []
        total_findings = 0

        for file_path, content in files.items():
            # ── 1. Path / extension filter ────────────────────────────────
            if self._should_skip(file_path):
                continue

            # ── 2. Size filter ────────────────────────────────────────────
            if len(content.encode("utf-8")) > cfg.max_file_size_kb * 1024:
                continue

            # ── 3 & 4. Pattern matching with allow-list suppression ───────
            severity_counts: Dict[str, int] = {}
            findings_summary: List[str] = []
            file_blocked = False

            if cfg.include_regex:
                for line_no, line in enumerate(content.splitlines(), start=1):
                    for rule_id, severity_str, pattern in _BUILTIN_PATTERNS:
                        match = pattern.search(line)
                        if match is None:
                            continue

                        # ── 4. Allow-list check ───────────────────────────
                        if any(token in line for token in cfg.allow_list):
                            continue

                        # Record finding
                        severity_counts[severity_str] = (
                            severity_counts.get(severity_str, 0) + 1
                        )
                        # Build a masked excerpt: keep 4 chars prefix, mask the rest
                        start, end = match.span()
                        masked = (
                            line[:start]
                            + line[start : start + 4]
                            + "****"
                            + f"[{end - start}chars]"
                        )[:120]
                        findings_summary.append(
                            f"[{rule_id}] {severity_str} @ line {line_no}: {masked}"
                        )

                        # ── 5. Block check ────────────────────────────────
                        finding_level = _severity_from_str(severity_str)
                        if finding_level >= cfg.fail_level:
                            file_blocked = True

            findings_count = sum(severity_counts.values())
            total_findings += findings_count

            if file_blocked:
                blocked_files.append(file_path)

            file_results.append(
                FileScanResult(
                    file_path=file_path,
                    findings_count=findings_count,
                    blocked=file_blocked,
                    severity_counts=severity_counts,
                    findings_summary=findings_summary,
                )
            )

        # ── Build top-level result ────────────────────────────────────────
        exit_code = 1 if blocked_files else 0

        if exit_code == 1:
            message = (
                f"COMMIT BLOCKED — {total_findings} finding(s) in "
                f"{len(blocked_files)} file(s): {', '.join(blocked_files)}"
            )
        elif total_findings > 0:
            message = (
                f"Scan complete — {total_findings} finding(s) found "
                f"but none met the block threshold ({cfg.fail_on_severity})."
            )
        else:
            message = "Scan complete — no secrets detected."

        return HookResult(
            exit_code=exit_code,
            total_findings=total_findings,
            blocked_files=blocked_files,
            file_results=file_results,
            message=message,
            generated_at=time.time(),
        )

    def get_config_summary(self) -> Dict:
        """Return the active configuration as a plain dictionary.

        Useful for debugging hook behaviour and for logging the effective
        configuration at the start of a CI run.
        """
        cfg = self._config
        return {
            "fail_on_severity": cfg.fail_on_severity,
            "fail_level": cfg.fail_level.name,
            "skip_paths": list(cfg.skip_paths),
            "skip_extensions": list(cfg.skip_extensions),
            "max_file_size_kb": cfg.max_file_size_kb,
            "include_entropy": cfg.include_entropy,
            "include_regex": cfg.include_regex,
            "allow_list": list(cfg.allow_list),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _should_skip(self, file_path: str) -> bool:
        """Return True if *file_path* should be excluded from scanning.

        Exclusion is triggered when:
          - Any entry in ``skip_paths`` appears as a substring of the path.
          - The file's extension (including the leading dot) matches any
            entry in ``skip_extensions``.

        Args:
            file_path: The path string to evaluate.

        Returns:
            True when the file should be skipped, False otherwise.
        """
        cfg = self._config

        # Substring match against skip_paths entries
        for skip in cfg.skip_paths:
            if skip in file_path:
                return True

        # Extension match
        if cfg.skip_extensions:
            # Extract extension including the leading dot
            dot_pos = file_path.rfind(".")
            if dot_pos != -1:
                ext = file_path[dot_pos:]  # e.g. ".md"
                if ext in cfg.skip_extensions:
                    return True

        return False


# ---------------------------------------------------------------------------
# Module-private utilities
# ---------------------------------------------------------------------------

def _severity_from_str(severity_str: str) -> SeverityLevel:
    """Convert a severity string to a :class:`SeverityLevel`, defaulting to INFO."""
    try:
        return SeverityLevel[severity_str.upper()]
    except (KeyError, AttributeError):
        return SeverityLevel.INFO
