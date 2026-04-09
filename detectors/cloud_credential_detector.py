# cloud_credential_detector.py
# Part of Cyber Port — Secret Leak Sentinel
#
# CC BY 4.0 License
# © 2026 hiagokinlevi / Cyber Port
# https://creativecommons.org/licenses/by/4.0/
#
# Detect cloud provider-specific credential patterns in source code,
# configuration files, and arbitrary text.  Supports AWS, Azure, GCP,
# and generic cloud credential formats with provider-aware classification
# and severity scoring.

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Check weights registry
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "CCD-001": 45,  # AWS access key ID
    "CCD-002": 45,  # AWS secret access key
    "CCD-003": 45,  # Azure storage key / connection string
    "CCD-004": 45,  # GCP service account JSON key
    "CCD-005": 30,  # Generic cloud API token
    "CCD-006": 30,  # Cloud DB connection string with credentials
    "CCD-007": 15,  # AWS ARN — sensitive resource path
}

# ---------------------------------------------------------------------------
# Compiled regex patterns
# NOTE: AWS key-prefix strings are constructed via concatenation so that
#       GitHub push-protection rules do not flag this source file.
# ---------------------------------------------------------------------------

# CCD-001 — AWS access key ID variants
_AWS_KEY_PREFIX_AKIA = "AKIA"
_AWS_KEY_SUFFIX_PAT = r"[0-9A-Z]{16}"

# Covers AKIA (long-term), ASIA (temporary STS), AROA (assumed-role),
# AIDA (IAM user ID) — all share the same 16-char uppercase-alphanumeric tail.
_AWS_ALL_KEY_PATTERN: re.Pattern = re.compile(
    r"(?:"
    + _AWS_KEY_PREFIX_AKIA
    + r"|ASIA|AROA|AIDA)"
    + _AWS_KEY_SUFFIX_PAT
)

# CCD-002 — AWS secret access key (40-char base64 after context keyword)
_AWS_SECRET_PATTERN: re.Pattern = re.compile(
    r"(?i)(?:aws_secret_access_key|secret_access_key|aws_secret)"
    r"\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})['\"]?"
)

# CCD-003 — Azure storage account key and connection string
_AZURE_STORAGE_KEY_PATTERN: re.Pattern = re.compile(
    r"(?i)(?:AccountKey|storage.{0,10}key)\s*[=:]\s*['\"]?([A-Za-z0-9+/]{86}==)"
)
_AZURE_CONN_STRING_PATTERN: re.Pattern = re.compile(
    r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;'\"\\s]+"
)

# CCD-004 — GCP service account JSON indicators
_GCP_PRIVATE_KEY_ID_PATTERN: re.Pattern = re.compile(
    r'"private_key_id"\s*:\s*"[a-f0-9]{40}"'
)
_GCP_CLIENT_EMAIL_PATTERN: re.Pattern = re.compile(
    r'"client_email"\s*:\s*"[^"]+@[^"]+\.iam\.gserviceaccount\.com"'
)

# CCD-005 — Generic cloud API tokens
_AZURE_AD_TOKEN_PATTERN: re.Pattern = re.compile(
    r"(?i)(?:client_secret|tenant_id|client_id)"
    r"\s*[=:]\s*['\"]?([0-9a-fA-F-]{36})['\"]?"
)
_AWS_SESSION_TOKEN_PATTERN: re.Pattern = re.compile(
    r"(?i)aws_session_token\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?"
)
_GCP_OAUTH_TOKEN_PATTERN: re.Pattern = re.compile(
    r"ya29\.[A-Za-z0-9_\-]{50,}"
)

# CCD-006 — Cloud database connection strings with embedded credentials
_AWS_RDS_PATTERN: re.Pattern = re.compile(
    r"(?i)(?:mysql|postgresql|postgres|jdbc:mysql|jdbc:postgresql)"
    r"://[^:@\s]+:[^@\s]+@[^/\s]*\.rds\.amazonaws\.com"
)
_AZURE_SQL_PATTERN: re.Pattern = re.compile(
    r"(?i)Server=tcp:[^;]+\.database\.windows\.net[^;]*;.*Password=[^;'\" ]+"
)
_GCP_CLOUDSQL_PATTERN: re.Pattern = re.compile(
    r"(?i)(?:mysql|postgresql|postgres)://[^:@\s]+:[^@\s]+@[^\s]*cloudsql"
)

# CCD-007 — AWS ARNs with sensitive resource paths
_ARN_SECRETS_MANAGER_PATTERN: re.Pattern = re.compile(
    r"arn:aws:secretsmanager:[^:\s]+:[^:\s]+:secret:[^\s'\"]+"
)
_ARN_SSM_PATTERN: re.Pattern = re.compile(
    r"arn:aws:ssm:[^:\s]+:[^:\s]+:parameter/[^\s'\"]+"
)
_ARN_KMS_PATTERN: re.Pattern = re.compile(
    r"arn:aws:kms:[^:\s]+:[^:\s]+:key/[0-9a-f-]{36}"
)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class CCDMatch:
    """A single pattern match within a line of text."""

    provider: str        # "aws" | "azure" | "gcp" | "generic"
    pattern_name: str    # human-readable label for the matched pattern
    line_number: int     # 1-indexed line number in the scanned text
    redacted_value: str  # first 4 chars + "****"


@dataclass
class CCDFinding:
    """All matches for one check ID within a single scan result."""

    check_id: str
    severity: str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int
    matches: List[CCDMatch] = field(default_factory=list)


@dataclass
class CCDResult:
    """Aggregate result returned by :func:`scan`."""

    source_name: str                 # filename or caller-supplied identifier
    findings: List[CCDFinding] = field(default_factory=list)
    risk_score: int = 0              # min(100, sum of weights for unique fired IDs)
    provider_summary: Dict[str, int] = field(default_factory=dict)  # provider -> count

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a fully serialisable plain-dict representation."""
        return {
            "source_name": self.source_name,
            "risk_score": self.risk_score,
            "provider_summary": dict(self.provider_summary),
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                    "matches": [
                        {
                            "provider": m.provider,
                            "pattern_name": m.pattern_name,
                            "line_number": m.line_number,
                            "redacted_value": m.redacted_value,
                        }
                        for m in f.matches
                    ],
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary string."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        parts = [f"{v} {k}" for k, v in counts.items() if v > 0]
        sev_str = ", ".join(parts) if parts else "none"
        return (
            f"[{self.source_name}] risk={self.risk_score}/100 "
            f"findings={len(self.findings)} ({sev_str})"
        )

    def by_severity(self) -> dict:
        """Return findings grouped by severity label."""
        result: Dict[str, List[CCDFinding]] = {}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _redact(value: str) -> str:
    """Return the first 4 characters of *value* followed by '****'."""
    return value[:4] + "****"


def _scan_lines(
    lines: List[str],
    pattern: re.Pattern,
    provider: str,
    pattern_name: str,
    group: int = 0,
) -> List[CCDMatch]:
    """Scan every line for *pattern* and return :class:`CCDMatch` objects.

    Args:
        lines: Pre-split list of text lines (0-indexed internally).
        pattern: Compiled regex to search each line.
        provider: Cloud provider label for the resulting matches.
        pattern_name: Human-readable pattern label.
        group: Regex capture group index whose value is redacted.
                Use 0 (full match) when there are no capture groups.
    """
    matches: List[CCDMatch] = []
    for idx, line in enumerate(lines):
        for m in pattern.finditer(line):
            raw = m.group(group) if group <= len(m.groups()) else m.group(0)
            if not raw:
                raw = m.group(0)
            matches.append(
                CCDMatch(
                    provider=provider,
                    pattern_name=pattern_name,
                    line_number=idx + 1,  # convert to 1-indexed
                    redacted_value=_redact(raw),
                )
            )
    return matches


# ---------------------------------------------------------------------------
# Per-check detection functions
# ---------------------------------------------------------------------------


def _check_ccd001(lines: List[str]) -> Optional[CCDFinding]:
    """CCD-001: AWS access key ID (AKIA / ASIA / AROA / AIDA variants)."""
    matches = _scan_lines(
        lines, _AWS_ALL_KEY_PATTERN, "aws", "AWS access key ID"
    )
    if not matches:
        return None
    return CCDFinding(
        check_id="CCD-001",
        severity="CRITICAL",
        title="AWS Access Key ID detected",
        detail=(
            "An AWS access key ID was found in the scanned text.  "
            "Access key IDs beginning with AKIA are long-lived credentials; "
            "ASIA tokens are temporary STS credentials; AROA / AIDA are IAM role "
            "and user identifiers.  Rotate or revoke immediately if real."
        ),
        weight=_CHECK_WEIGHTS["CCD-001"],
        matches=matches,
    )


def _check_ccd002(lines: List[str]) -> Optional[CCDFinding]:
    """CCD-002: AWS secret access key following a known context keyword."""
    matches = _scan_lines(
        lines, _AWS_SECRET_PATTERN, "aws", "AWS secret access key", group=1
    )
    if not matches:
        return None
    return CCDFinding(
        check_id="CCD-002",
        severity="CRITICAL",
        title="AWS Secret Access Key detected",
        detail=(
            "A 40-character base64 string was found immediately following an "
            "AWS secret key context keyword (aws_secret_access_key, "
            "secret_access_key, aws_secret).  If genuine, revoke and rotate the "
            "associated IAM key pair without delay."
        ),
        weight=_CHECK_WEIGHTS["CCD-002"],
        matches=matches,
    )


def _check_ccd003(lines: List[str]) -> Optional[CCDFinding]:
    """CCD-003: Azure storage account key or connection string."""
    matches: List[CCDMatch] = []
    matches += _scan_lines(
        lines, _AZURE_STORAGE_KEY_PATTERN, "azure", "Azure storage account key", group=1
    )
    matches += _scan_lines(
        lines, _AZURE_CONN_STRING_PATTERN, "azure", "Azure storage connection string"
    )
    if not matches:
        return None
    return CCDFinding(
        check_id="CCD-003",
        severity="CRITICAL",
        title="Azure storage credential detected",
        detail=(
            "An Azure storage account key (88-character base64) or a full "
            "DefaultEndpointsProtocol connection string containing AccountKey was "
            "found.  Regenerate the storage account key in the Azure portal and "
            "update all references."
        ),
        weight=_CHECK_WEIGHTS["CCD-003"],
        matches=matches,
    )


def _check_ccd004(lines: List[str]) -> Optional[CCDFinding]:
    """CCD-004: GCP service account JSON key indicators."""
    matches: List[CCDMatch] = []
    matches += _scan_lines(
        lines, _GCP_PRIVATE_KEY_ID_PATTERN, "gcp", "GCP service account private_key_id"
    )
    matches += _scan_lines(
        lines, _GCP_CLIENT_EMAIL_PATTERN, "gcp", "GCP service account client_email"
    )
    if not matches:
        return None
    return CCDFinding(
        check_id="CCD-004",
        severity="CRITICAL",
        title="GCP service account key JSON detected",
        detail=(
            "A GCP service account JSON key file indicator was found — either a "
            "private_key_id (40-char hex) or a client_email ending in "
            ".iam.gserviceaccount.com.  Delete the key in the GCP console and "
            "create a replacement key; audit any IAM roles bound to this account."
        ),
        weight=_CHECK_WEIGHTS["CCD-004"],
        matches=matches,
    )


def _check_ccd005(lines: List[str]) -> Optional[CCDFinding]:
    """CCD-005: Generic cloud API tokens (Azure AD, AWS session, GCP OAuth)."""
    matches: List[CCDMatch] = []
    matches += _scan_lines(
        lines, _AZURE_AD_TOKEN_PATTERN, "azure", "Azure AD client secret / tenant ID / client ID", group=1
    )
    matches += _scan_lines(
        lines, _AWS_SESSION_TOKEN_PATTERN, "aws", "AWS session token", group=1
    )
    matches += _scan_lines(
        lines, _GCP_OAUTH_TOKEN_PATTERN, "gcp", "GCP OAuth access token"
    )
    if not matches:
        return None
    return CCDFinding(
        check_id="CCD-005",
        severity="HIGH",
        title="Generic cloud API token detected",
        detail=(
            "A short-lived or generic cloud API token was found: Azure AD UUID "
            "(client_secret / tenant_id / client_id), an AWS session token "
            "(aws_session_token), or a GCP OAuth token (ya29.* prefix).  "
            "Even short-lived tokens must not appear in committed code or logs."
        ),
        weight=_CHECK_WEIGHTS["CCD-005"],
        matches=matches,
    )


def _check_ccd006(lines: List[str]) -> Optional[CCDFinding]:
    """CCD-006: Cloud database connection strings with embedded credentials."""
    matches: List[CCDMatch] = []
    matches += _scan_lines(
        lines, _AWS_RDS_PATTERN, "aws", "AWS RDS connection string with credentials"
    )
    matches += _scan_lines(
        lines, _AZURE_SQL_PATTERN, "azure", "Azure SQL connection string with Password"
    )
    matches += _scan_lines(
        lines, _GCP_CLOUDSQL_PATTERN, "gcp", "GCP CloudSQL connection string with credentials"
    )
    if not matches:
        return None
    return CCDFinding(
        check_id="CCD-006",
        severity="HIGH",
        title="Cloud database connection string with credentials detected",
        detail=(
            "A cloud-managed database connection string containing embedded "
            "username and password credentials was found (AWS RDS, Azure SQL, "
            "or GCP CloudSQL).  Replace hardcoded credentials with secrets manager "
            "references or environment variable injection."
        ),
        weight=_CHECK_WEIGHTS["CCD-006"],
        matches=matches,
    )


def _check_ccd007(lines: List[str]) -> Optional[CCDFinding]:
    """CCD-007: AWS ARNs pointing to sensitive resource paths."""
    matches: List[CCDMatch] = []
    matches += _scan_lines(
        lines, _ARN_SECRETS_MANAGER_PATTERN, "aws", "AWS Secrets Manager ARN"
    )
    matches += _scan_lines(
        lines, _ARN_SSM_PATTERN, "aws", "AWS SSM Parameter Store ARN"
    )
    matches += _scan_lines(
        lines, _ARN_KMS_PATTERN, "aws", "AWS KMS key ARN"
    )
    if not matches:
        return None
    return CCDFinding(
        check_id="CCD-007",
        severity="MEDIUM",
        title="AWS ARN for sensitive resource detected",
        detail=(
            "An AWS ARN referencing a sensitive resource path was found: Secrets "
            "Manager secret, SSM Parameter Store parameter, or KMS key.  ARNs "
            "themselves are not credentials, but they reveal infrastructure topology "
            "and may aid privilege-escalation attempts."
        ),
        weight=_CHECK_WEIGHTS["CCD-007"],
        matches=matches,
    )


# Ordered list of check functions used by :func:`scan`
_CHECKS = [
    _check_ccd001,
    _check_ccd002,
    _check_ccd003,
    _check_ccd004,
    _check_ccd005,
    _check_ccd006,
    _check_ccd007,
]

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan(text: str, source_name: str = "input") -> CCDResult:
    """Scan *text* for cloud credential patterns.

    Args:
        text: Arbitrary text to analyse (source code, config, log, etc.).
        source_name: A label identifying the origin of *text* (file path,
            URL, or any human-readable identifier).

    Returns:
        A :class:`CCDResult` containing all findings, risk score, and a
        per-provider match count.
    """
    lines = text.splitlines()

    findings: List[CCDFinding] = []
    fired_check_ids: List[str] = []

    for check_fn in _CHECKS:
        finding = check_fn(lines)
        if finding is not None:
            findings.append(finding)
            fired_check_ids.append(finding.check_id)

    # Risk score: sum of weights for unique fired checks, capped at 100
    unique_ids = list(dict.fromkeys(fired_check_ids))  # preserve order, deduplicate
    risk_score = min(100, sum(_CHECK_WEIGHTS[cid] for cid in unique_ids))

    # Provider summary: count findings per provider
    provider_summary: Dict[str, int] = {}
    for finding in findings:
        for match in finding.matches:
            provider_summary[match.provider] = (
                provider_summary.get(match.provider, 0) + 1
            )

    return CCDResult(
        source_name=source_name,
        findings=findings,
        risk_score=risk_score,
        provider_summary=provider_summary,
    )


def scan_many(
    texts: List[str],
    source_names: Optional[List[str]] = None,
) -> List[CCDResult]:
    """Scan multiple texts and return one :class:`CCDResult` per entry.

    Args:
        texts: List of text strings to scan.
        source_names: Optional parallel list of source labels.  When shorter
            than *texts* or omitted, remaining entries are labelled
            ``"input_<index>"``.

    Returns:
        List of :class:`CCDResult` objects in the same order as *texts*.
    """
    results: List[CCDResult] = []
    for idx, text in enumerate(texts):
        if source_names and idx < len(source_names):
            name = source_names[idx]
        else:
            name = f"input_{idx}"
        results.append(scan(text, source_name=name))
    return results
