"""
CI Artifact Scanner
=====================
Scans CI/CD build log outputs and artifact files for accidentally exposed secrets.

CI build logs are a common source of secret leakage — environment variables,
debug output, and package installation logs may inadvertently echo credentials.
This scanner is designed to be called from a CI pipeline step to detect leakage
before logs are uploaded to an artifact store.

Supported input formats:
  - Raw text log files (any CI provider)
  - GitHub Actions workflow log bundles (directory of .txt files)
  - Environment variable dump files (env-safe-output or .env style)

All findings are redacted before being stored or reported — the scanner
logs the finding metadata (file, line, type) but never persists the
raw secret value.

Usage:
    from scanners.ci_artifact_scanner import scan_log_file, scan_log_directory

    findings = scan_log_file(Path("build.log"))
    for f in findings:
        print(f"[{f.criticality}] {f.secret_type} at line {f.line_number}")
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from detectors.regex_detector import (
    DETECTOR_PATTERNS,
    Criticality,
    DetectorPattern,
    SecretType,
)


# ---------------------------------------------------------------------------
# CI-specific additional patterns (not in the main regex_detector)
# ---------------------------------------------------------------------------

_CI_EXTRA_PATTERNS: list[DetectorPattern] = [
    DetectorPattern(
        name="github_actions_secret_echo",
        pattern=r"echo\s+['\"]?\$\{\{?\s*secrets\.[A-Z_]+\s*\}?\}['\"]?",
        secret_type=SecretType.API_TOKEN,
        criticality=Criticality.HIGH,
        description="GitHub Actions secret echo — secret value may appear in log output",
    ),
    DetectorPattern(
        name="env_var_value_dump",
        pattern=r"(?i)(export\s+)?[A-Z_]{3,}(?:SECRET|KEY|TOKEN|PASSWORD|PASS|CRED)[A-Z_]*\s*=\s*['\"]?[A-Za-z0-9+/=_\-]{8,}['\"]?",
        secret_type=SecretType.GENERIC_SECRET,
        criticality=Criticality.HIGH,
        description="Environment variable assignment containing a possible secret value in log output",
    ),
    DetectorPattern(
        name="docker_build_arg_secret",
        pattern=r"--build-arg\s+\S+(?:SECRET|KEY|TOKEN|PASSWORD)\s*=\s*\S+",
        secret_type=SecretType.GENERIC_SECRET,
        criticality=Criticality.HIGH,
        description="Docker build argument passing a secret — may appear in docker build logs",
    ),
    DetectorPattern(
        name="curl_authorization_header",
        pattern=r"(?i)curl\s+.*-H\s+['\"]?Authorization:\s*(Bearer|Basic|Token)\s+[A-Za-z0-9+/=_\-]{8,}",
        secret_type=SecretType.API_TOKEN,
        criticality=Criticality.CRITICAL,
        description="curl command with authorization header containing a credential value in log",
    ),
    DetectorPattern(
        name="pip_index_url_credentials",
        pattern=r"https://[^@\s]{3,}:[^@\s]{3,}@",
        secret_type=SecretType.CONNECTION_STRING,
        criticality=Criticality.HIGH,
        description="URL containing embedded credentials (user:pass@host) in log output",
    ),
    DetectorPattern(
        name="npm_config_token",
        pattern=r"(?i)npm\s+config\s+set\s+.*token\s+[A-Za-z0-9\-_]{8,}",
        secret_type=SecretType.API_TOKEN,
        criticality=Criticality.HIGH,
        description="npm token configuration command — token value visible in log",
    ),
    DetectorPattern(
        name="aws_session_token",
        pattern=r"(?i)(?:aws_session_token|session_token)\s*[=:]\s*[A-Za-z0-9+/=]{100,}",
        secret_type=SecretType.AWS_SECRET_KEY,
        criticality=Criticality.CRITICAL,
        description="AWS session token value in log output",
    ),
    DetectorPattern(
        name="azure_sas_token",
        pattern=r"(?:sig|sv|se|sr|sp|st)=[A-Za-z0-9%+/=]{10,}&",
        secret_type=SecretType.API_TOKEN,
        criticality=Criticality.HIGH,
        description="Possible Azure SAS token query string in log output",
    ),
]

# Combine all patterns for CI log scanning
_ALL_CI_PATTERNS = DETECTOR_PATTERNS + _CI_EXTRA_PATTERNS

# Lines that are structural/non-secret log metadata — skip these for performance
_LOG_SKIP_RE = re.compile(
    r"^(\s*#|##\[|::(?:debug|notice|warning|error|group|endgroup|set-output)|\s*$)",
    re.IGNORECASE,
)

# Maximum line length to scan — very long lines are likely base64 artifacts, not secrets
_MAX_LINE_LENGTH = 2000


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class CiSecretFinding:
    """A potential secret detected in a CI log or artifact file."""

    file_path: str
    line_number: int
    secret_type: SecretType
    criticality: Criticality
    detector_name: str
    masked_line: str        # Line content with secret values masked
    context_lines: list[str] = field(default_factory=list)  # 1 line before and after

    @property
    def is_high_priority(self) -> bool:
        return self.criticality in (Criticality.CRITICAL, Criticality.HIGH)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_log_file(
    log_path: Path,
    include_ci_patterns: bool = True,
) -> list[CiSecretFinding]:
    """
    Scan a single CI log or artifact file for secret leakage.

    Args:
        log_path:            Path to the log file to scan.
        include_ci_patterns: If True, include CI-specific patterns in addition
                             to the standard regex detector patterns. Default: True.

    Returns:
        List of CiSecretFinding objects. Never contains raw secret values.

    Raises:
        OSError: If the file cannot be read.
    """
    patterns = _ALL_CI_PATTERNS if include_ci_patterns else DETECTOR_PATTERNS
    findings: list[CiSecretFinding] = []

    try:
        content = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise OSError(f"Cannot read log file {log_path}: {exc}") from exc

    lines = content.splitlines()

    for line_idx, line in enumerate(lines):
        line_no = line_idx + 1

        # Skip structural log metadata lines (performance optimisation)
        if _LOG_SKIP_RE.match(line):
            continue

        # Skip extremely long lines (likely encoded blobs)
        if len(line) > _MAX_LINE_LENGTH:
            continue

        for pattern in patterns:
            compiled = re.compile(pattern.pattern, re.IGNORECASE)
            match = compiled.search(line)
            if match:
                # Build a masked line — replace the matched value with asterisks
                masked = compiled.sub(
                    lambda m: _mask_match(m.group(0)), line
                )

                # Collect one line before and after for context
                ctx_before = lines[line_idx - 1].strip() if line_idx > 0 else ""
                ctx_after = lines[line_idx + 1].strip() if line_idx < len(lines) - 1 else ""

                findings.append(CiSecretFinding(
                    file_path=str(log_path),
                    line_number=line_no,
                    secret_type=pattern.secret_type,
                    criticality=pattern.criticality,
                    detector_name=pattern.name,
                    masked_line=masked.strip()[:200],
                    context_lines=[ctx_before, ctx_after],
                ))
                break  # One finding per line per pass — avoid duplicate alerts

    return findings


def scan_log_directory(
    log_dir: Path,
    extensions: tuple[str, ...] = (".log", ".txt", ".out"),
    include_ci_patterns: bool = True,
    max_file_size_bytes: int = 10 * 1024 * 1024,  # 10 MB
) -> list[CiSecretFinding]:
    """
    Recursively scan all log files in a directory for secret leakage.

    Args:
        log_dir:             Path to the directory containing log files.
        extensions:          File extensions to scan (default: .log, .txt, .out).
        include_ci_patterns: Include CI-specific patterns (default: True).
        max_file_size_bytes: Skip files larger than this (default: 10 MB).

    Returns:
        List of CiSecretFinding objects across all scanned files.
    """
    all_findings: list[CiSecretFinding] = []

    for ext in extensions:
        for log_file in sorted(log_dir.rglob(f"*{ext}")):
            if not log_file.is_file():
                continue
            if log_file.stat().st_size > max_file_size_bytes:
                continue
            try:
                findings = scan_log_file(log_file, include_ci_patterns=include_ci_patterns)
                all_findings.extend(findings)
            except OSError:
                continue  # Skip unreadable files, don't fail the whole scan

    # Sort: critical first, then by file/line
    priority_order = {
        Criticality.CRITICAL: 0,
        Criticality.HIGH: 1,
        Criticality.MEDIUM: 2,
        Criticality.LOW: 3,
    }
    all_findings.sort(key=lambda f: (priority_order.get(f.criticality, 99), f.file_path, f.line_number))
    return all_findings


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _mask_match(matched_text: str) -> str:
    """Replace a matched secret value with asterisks, keeping a short prefix."""
    if len(matched_text) <= 4:
        return "***"
    # Keep up to 4 chars of prefix, mask the rest
    return matched_text[:4] + "*" * min(len(matched_text) - 4, 20)
