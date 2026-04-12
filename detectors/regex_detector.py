"""
Regex-Based Secret Detector
============================
Detects potential secrets using curated regular expressions.

Patterns cover common credential types:
  - API tokens (generic, AWS, GitHub, Slack, etc.)
  - Private keys (PEM blocks)
  - Connection strings
  - High-entropy strings in assignment context

IMPORTANT: This detector produces candidates, not confirmed secrets.
All findings require human review before remediation.
"""
import base64
import json
import re
from dataclasses import dataclass
from typing import Optional
from enum import Enum


class SecretType(str, Enum):
    API_TOKEN = "api_token"
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    CLOUD_CREDENTIAL = "cloud_credential"
    GITHUB_TOKEN = "github_token"
    STRIPE_KEY = "stripe_key"
    TWILIO_TOKEN = "twilio_token"
    SENDGRID_KEY = "sendgrid_key"
    PRIVATE_KEY = "private_key"
    CONNECTION_STRING = "connection_string"
    GENERIC_SECRET = "generic_secret"
    POSSIBLE_PASSWORD = "possible_password"
    CERTIFICATE_MATERIAL = "certificate_material"


class Criticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DetectorPattern:
    name: str
    pattern: str
    secret_type: SecretType
    criticality: Criticality
    description: str


# AWS temporary STS access keys use the ASIA prefix. Treat them like
# long-lived AKIA access keys so one detector covers both credential forms.
_AWS_ACCESS_KEY_PREFIX_PATTERN = r"(?:AKIA|ASIA)"


# Curated detector patterns.
# Ordered from most specific (and thus most reliable) to most generic.
DETECTOR_PATTERNS: list[DetectorPattern] = [
    DetectorPattern(
        name="aws_access_key_id",
        pattern=_AWS_ACCESS_KEY_PREFIX_PATTERN + r"[0-9A-Z]{16}",
        secret_type=SecretType.AWS_ACCESS_KEY,
        criticality=Criticality.CRITICAL,
        description="AWS Access Key ID — if exposed, could grant access to AWS resources",
    ),
    DetectorPattern(
        name="github_personal_access_token",
        pattern=r"ghp_[A-Za-z0-9]{36}",
        secret_type=SecretType.GITHUB_TOKEN,
        criticality=Criticality.CRITICAL,
        description="GitHub Personal Access Token (classic)",
    ),
    DetectorPattern(
        name="github_oauth_token",
        pattern=r"gho_[A-Za-z0-9]{36}",
        secret_type=SecretType.GITHUB_TOKEN,
        criticality=Criticality.CRITICAL,
        description="GitHub OAuth Token",
    ),
    DetectorPattern(
        name="github_fine_grained_pat",
        pattern=r"github_pat_[A-Za-z0-9_]{20,255}",
        secret_type=SecretType.GITHUB_TOKEN,
        criticality=Criticality.CRITICAL,
        description="GitHub fine-grained personal access token",
    ),
    DetectorPattern(
        name="github_app_user_token",
        pattern=r"ghu_[A-Za-z0-9]{20,255}",
        secret_type=SecretType.GITHUB_TOKEN,
        criticality=Criticality.CRITICAL,
        description="GitHub App user access token",
    ),
    DetectorPattern(
        name="github_app_installation_token",
        pattern=r"ghs_[A-Za-z0-9]{20,255}",
        secret_type=SecretType.GITHUB_TOKEN,
        criticality=Criticality.CRITICAL,
        description="GitHub App installation access token",
    ),
    DetectorPattern(
        name="github_app_refresh_token",
        pattern=r"ghr_[A-Za-z0-9]{20,255}",
        secret_type=SecretType.GITHUB_TOKEN,
        criticality=Criticality.CRITICAL,
        description="GitHub App refresh token",
    ),
    DetectorPattern(
        name="stripe_live_secret_key",
        pattern=r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b",
        secret_type=SecretType.STRIPE_KEY,
        criticality=Criticality.CRITICAL,
        description="Stripe live secret or restricted API key",
    ),
    DetectorPattern(
        name="twilio_auth_token_assignment",
        pattern=(
            r"(?i)(?:twilio[_-]?)?(?:auth[_-]?token|api[_-]?secret)"
            r"\s*[=:]\s*[\"']?([a-f0-9]{32})[\"']?"
        ),
        secret_type=SecretType.TWILIO_TOKEN,
        criticality=Criticality.CRITICAL,
        description="Twilio auth token or API secret in assignment context",
    ),
    DetectorPattern(
        name="sendgrid_api_key",
        pattern=r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{32,}\b",
        secret_type=SecretType.SENDGRID_KEY,
        criticality=Criticality.CRITICAL,
        description="SendGrid API key",
    ),
    DetectorPattern(
        name="slack_bearer_token",
        pattern=r"\bxox(?:a|b|p|r|s)-[A-Za-z0-9-]{24,}\b",
        secret_type=SecretType.API_TOKEN,
        criticality=Criticality.CRITICAL,
        description="Slack bearer token (bot, user, admin, config, or refresh)",
    ),
    DetectorPattern(
        name="slack_app_token",
        pattern=r"\bxapp-\d-[A-Za-z0-9-]{24,}\b",
        secret_type=SecretType.API_TOKEN,
        criticality=Criticality.CRITICAL,
        description="Slack app-level token",
    ),
    DetectorPattern(
        name="npm_access_token",
        pattern=r"\bnpm_[A-Za-z0-9]{36}\b",
        secret_type=SecretType.API_TOKEN,
        criticality=Criticality.CRITICAL,
        description="npm access token",
    ),
    DetectorPattern(
        name="azure_sas_url",
        pattern=(
            r"""(?ix)
            https?://[^\s"'?]+\?
            (?=[^\s"']*\bsv=)
            (?=[^\s"']*\b(?:sig|se|sp)=)
            [^\s"']*\bsig=[A-Za-z0-9%/+]{16,}[^\s"']*
            """
        ),
        secret_type=SecretType.CLOUD_CREDENTIAL,
        criticality=Criticality.CRITICAL,
        description="Azure SAS URL with signed access token parameters",
    ),
    DetectorPattern(
        name="azure_storage_connection_string",
        pattern=(
            r"(?i)\bDefaultEndpointsProtocol=https?;"
            r"AccountName=[^;]+;"
            r"AccountKey=[^;\"'\s]+"
        ),
        secret_type=SecretType.CONNECTION_STRING,
        criticality=Criticality.CRITICAL,
        description="Azure storage connection string with AccountKey",
    ),
    DetectorPattern(
        name="gcp_service_account_private_key_id",
        pattern=r'"private_key_id"\s*:\s*"[a-f0-9]{40}"',
        secret_type=SecretType.CLOUD_CREDENTIAL,
        criticality=Criticality.CRITICAL,
        description="GCP service account JSON private_key_id field",
    ),
    DetectorPattern(
        name="gcp_service_account_client_email",
        pattern=r'"client_email"\s*:\s*"[^"]+@[^"]+\.iam\.gserviceaccount\.com"',
        secret_type=SecretType.CLOUD_CREDENTIAL,
        criticality=Criticality.HIGH,
        description="GCP service account JSON client_email field",
    ),
    DetectorPattern(
        name="vault_token_modern",
        pattern=r"\b(?:hvs|hvb|hvr)\.[A-Za-z0-9_-]{24,}\b",
        secret_type=SecretType.API_TOKEN,
        criticality=Criticality.CRITICAL,
        description="HashiCorp Vault service, batch, or recovery token",
    ),
    DetectorPattern(
        name="vault_token_legacy_assignment",
        pattern=(
            r"(?i)(?:x-vault-token|vault[_-]?token)\s*[:=]\s*[\"']?"
            r"(?:s|b|r)\.[A-Za-z0-9_-]{24,}[\"']?"
        ),
        secret_type=SecretType.API_TOKEN,
        criticality=Criticality.CRITICAL,
        description="Legacy HashiCorp Vault token in assignment or header context",
    ),
    DetectorPattern(
        name="pem_private_key",
        pattern=r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        secret_type=SecretType.PRIVATE_KEY,
        criticality=Criticality.CRITICAL,
        description="PEM or PKCS#8 private key block",
    ),
    DetectorPattern(
        name="ssh2_private_key",
        pattern=r"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----",
        secret_type=SecretType.PRIVATE_KEY,
        criticality=Criticality.CRITICAL,
        description="SSH.com SSH2 private key block",
    ),
    DetectorPattern(
        name="putty_private_key",
        pattern=(
            r"PuTTY-User-Key-File-(?:2|3):\s*"
            r"(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp(?:256|384|521))"
        ),
        secret_type=SecretType.PRIVATE_KEY,
        criticality=Criticality.CRITICAL,
        description="PuTTY PPK private key header",
    ),
    DetectorPattern(
        name="jwt_weak_or_unsigned",
        pattern=(
            r"(?<![A-Za-z0-9_-])(?:Bearer\s+)?"
            r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{0,}"
            r"(?![A-Za-z0-9_-])"
        ),
        secret_type=SecretType.API_TOKEN,
        criticality=Criticality.HIGH,
        description="JWT bearer token using alg=none or HMAC signing",
    ),
    DetectorPattern(
        name="generic_api_key_assignment",
        pattern=r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']?[A-Za-z0-9+/]{20,}["\']?',
        secret_type=SecretType.API_TOKEN,
        criticality=Criticality.HIGH,
        description="API key in variable assignment context",
    ),
    DetectorPattern(
        name="password_assignment",
        pattern=r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']',
        secret_type=SecretType.POSSIBLE_PASSWORD,
        criticality=Criticality.HIGH,
        description="Password literal in assignment context",
    ),
    DetectorPattern(
        name="database_connection_string",
        pattern=r"(?i)(postgresql|postgres|mysql|mssql|mongodb)\+?://[^:\s]+:[^@\s]+@",
        secret_type=SecretType.CONNECTION_STRING,
        criticality=Criticality.HIGH,
        description="Database connection string with embedded credentials",
    ),
    DetectorPattern(
        name="aws_secret_access_key",
        pattern=r'(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*["\']?[A-Za-z0-9+/]{40}["\']?',
        secret_type=SecretType.AWS_SECRET_KEY,
        criticality=Criticality.CRITICAL,
        description="AWS Secret Access Key in assignment context",
    ),
    DetectorPattern(
        name="slack_webhook_url",
        pattern=r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        secret_type=SecretType.API_TOKEN,
        criticality=Criticality.HIGH,
        description="Slack incoming webhook URL — allows posting messages to a workspace channel",
    ),
    DetectorPattern(
        name="certificate_block",
        pattern=r"-----BEGIN CERTIFICATE-----",
        secret_type=SecretType.CERTIFICATE_MATERIAL,
        criticality=Criticality.LOW,
        description="PEM certificate block — public certificates are not secrets, but review context",
    ),
    DetectorPattern(
        name="generic_secret_assignment",
        pattern=r'(?i)(secret|token|auth[_-]?key|access[_-]?token)\s*[=:]\s*["\'][^"\']{16,}["\']',
        secret_type=SecretType.GENERIC_SECRET,
        criticality=Criticality.MEDIUM,
        description="Generic secret or token in assignment context",
    ),
]


@dataclass
class Finding:
    """A single secret detection finding."""
    detector_name: str
    secret_type: SecretType
    criticality: Criticality
    file_path: str
    line_number: int
    masked_excerpt: str  # Never store the actual secret — always mask it
    confidence: float    # 0.0 to 1.0
    policy_decision: str = "pending_review"
    suppressed: bool = False
    suppression_reason: Optional[str] = None


def _decode_base64url_json(value: str) -> Optional[dict]:
    """Decode a base64url-encoded JSON object, returning None on invalid input."""
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(value + padding)
        data = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    return data if isinstance(data, dict) else None


def _is_weak_or_unsigned_jwt(match_text: str) -> bool:
    """Return True only for JWTs whose header advertises alg=none or HMAC signing."""
    token = match_text.split()[-1]
    parts = token.split(".")
    if len(parts) != 3:
        return False

    header = _decode_base64url_json(parts[0])
    if not header:
        return False

    algorithm = str(header.get("alg", "")).upper()
    if algorithm == "NONE":
        return True

    return algorithm in {"HS256", "HS384", "HS512"}


def _should_emit_finding(detector: DetectorPattern, match: re.Match) -> bool:
    """Apply detector-specific validation beyond the base regex."""
    if detector.name == "jwt_weak_or_unsigned":
        return _is_weak_or_unsigned_jwt(match.group(0))

    return True


def _mask_value(line: str, match: re.Match) -> str:
    """
    Mask the matched secret value, keeping only a prefix for context.
    Never returns the full secret.
    """
    start, end = match.span()
    secret_len = end - start
    # Keep up to 4 characters of prefix for context; mask the rest
    masked = line[:start] + line[start:start+4] + "****" + f"[{secret_len}chars]"
    return masked[:120]  # Limit excerpt length to avoid leaking surrounding context


def scan_content(content: str, file_path: str) -> list[Finding]:
    """
    Scan file content for potential secrets.

    Args:
        content: Full file content as a string.
        file_path: Path to the file being scanned (used in findings).

    Returns:
        List of Finding objects. May be empty if no candidates found.
    """
    findings = []

    for line_no, line in enumerate(content.splitlines(), start=1):
        for detector in DETECTOR_PATTERNS:
            match = re.search(detector.pattern, line)
            if match and _should_emit_finding(detector, match):
                finding = Finding(
                    detector_name=detector.name,
                    secret_type=detector.secret_type,
                    criticality=detector.criticality,
                    file_path=file_path,
                    line_number=line_no,
                    masked_excerpt=_mask_value(line, match),
                    # Critical patterns (AWS key, GitHub token, PEM key) have high confidence
                    # due to their specific format; generic patterns have lower confidence
                    confidence=0.85 if detector.criticality == Criticality.CRITICAL else 0.65,
                )
                findings.append(finding)

    return findings
