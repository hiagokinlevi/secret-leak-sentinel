"""
Finding Schemas
================
Pydantic models for the canonical data structures in secret-leak-sentinel.

These models are used for:
  - Serialising findings to JSON for CI integration and downstream tooling
  - Validating suppression file entries
  - Typing the report generation layer

All models use Pydantic v2 conventions.

IMPORTANT: Secret values are NEVER stored in these models. All `excerpt` fields
must contain only masked values. Enforce this at the ingestion boundary.
"""
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class SecretType(str, Enum):
    """Classification of the detected secret type."""
    API_TOKEN = "api_token"
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
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
    """Severity level of a finding."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyDecision(str, Enum):
    """The policy decision applied to a finding."""
    PENDING_REVIEW = "pending_review"
    CONFIRMED_SECRET = "confirmed_secret"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"


class Finding(BaseModel):
    """
    Canonical representation of a single secret detection finding.

    The `masked_excerpt` field must always contain a masked version of the
    detected value. The full secret must never be stored here.
    """
    detector_name: str = Field(..., description="Name of the detector that produced this finding")
    secret_type: SecretType
    criticality: Criticality
    file_path: str = Field(..., description="Path to the file where the secret was detected")
    line_number: int = Field(..., gt=0, description="Line number within the file")
    masked_excerpt: str = Field(
        ...,
        description="Context around the finding with the secret value masked. NEVER store the actual value.",
    )
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detector confidence score (0-1)")
    policy_decision: PolicyDecision = PolicyDecision.PENDING_REVIEW
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    detected_at: datetime = Field(default_factory=datetime.utcnow)

    @field_validator("masked_excerpt")
    @classmethod
    def excerpt_must_be_masked(cls, v: str) -> str:
        """
        Validate that the excerpt does not look like an unmasked value.

        This is a best-effort check; full validation must be done at the detector level.
        """
        # Flag if the excerpt contains what looks like an unmasked AWS key
        import re
        if re.search(r"AKIA[0-9A-Z]{16}", v):
            raise ValueError(
                "masked_excerpt appears to contain an unmasked AWS Access Key ID. "
                "Mask the value before creating a Finding."
            )
        return v

    @model_validator(mode="after")
    def suppression_requires_reason(self) -> "Finding":
        """A suppressed finding must have a suppression reason."""
        if self.suppressed and not self.suppression_reason:
            raise ValueError("A suppressed finding must include a suppression_reason.")
        return self


class EntropyFinding(BaseModel):
    """A high-entropy string detection finding from the entropy detector."""
    file_path: str
    line_number: int = Field(..., gt=0)
    token: str = Field(..., description="Masked representation of the high-entropy token")
    entropy: float = Field(..., ge=0.0, description="Shannon entropy of the token in bits/char")
    masked_excerpt: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    detected_at: datetime = Field(default_factory=datetime.utcnow)


class SuppressedFinding(BaseModel):
    """
    A suppression rule loaded from .k1n-suppressions.yaml.

    Matches against findings to decide which should be silenced.
    """
    file: Optional[str] = Field(None, description="File path to suppress findings for")
    detector: Optional[str] = Field(None, description="Detector name to suppress for this file")
    reason: str = Field(..., description="Human-readable reason for the suppression")
    added_by: Optional[str] = None         # Who added this suppression
    expires: Optional[datetime] = None     # Optional expiry for time-limited suppressions

    @model_validator(mode="after")
    def must_have_file_or_detector(self) -> "SuppressedFinding":
        """A suppression rule must target at least a file or a detector."""
        if not self.file and not self.detector:
            raise ValueError("A SuppressedFinding must specify at least 'file' or 'detector'.")
        return self


class ScanResult(BaseModel):
    """
    Top-level container for a complete scan run's results.
    """
    scan_id: str
    scan_path: str
    scan_mode: str = Field(..., description="'filesystem', 'staged', or 'git'")
    policy_profile: str
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    total_files_scanned: int = 0
    findings: list[Finding] = Field(default_factory=list)
    entropy_findings: list[EntropyFinding] = Field(default_factory=list)

    @property
    def finding_counts(self) -> dict[str, int]:
        """Return finding counts grouped by criticality."""
        counts: dict[str, int] = {c.value: 0 for c in Criticality}
        for f in self.findings:
            counts[f.criticality.value] += 1
        return counts

    @property
    def has_critical_or_high(self) -> bool:
        """Return True if any finding is CRITICAL or HIGH."""
        return any(
            f.criticality in (Criticality.CRITICAL, Criticality.HIGH)
            for f in self.findings
        )
