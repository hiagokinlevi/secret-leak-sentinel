from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum
from typing import Dict, Optional, Any


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Base risk by secret family/type.
SECRET_TYPE_BASE_RISK: Dict[str, int] = {
    "private_key": 95,
    "cloud_api_key": 90,
    "database_password": 82,
    "oauth_token": 80,
    "jwt": 72,
    "generic_password": 65,
    "high_entropy_string": 55,
}


# Multiplier by verification confidence.
CONFIDENCE_MULTIPLIER: Dict[str, float] = {
    "confirmed": 1.0,
    "high": 0.9,
    "medium": 0.75,
    "low": 0.55,
    "unknown": 0.6,
}


# Exposure impact bonus by location.
EXPOSURE_LOCATION_BONUS: Dict[str, int] = {
    "public_repo": 25,
    "git_history": 18,
    "ci_logs": 20,
    "runtime_logs": 16,
    "working_tree": 8,
    "local_config": 10,
    "test_fixture": -12,
    "docs_example": -20,
}


@dataclass
class StructuredFinding:
    finding_id: str
    detector: str
    secret_type: str
    verification_confidence: str
    exposure_location: str
    file_path: str
    line_number: Optional[int]
    snippet: str
    score: int
    severity: SeverityLevel

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


def _clamp_score(value: float) -> int:
    return max(0, min(100, int(round(value))))


def score_finding(
    secret_type: str,
    verification_confidence: str,
    exposure_location: str,
) -> int:
    base = SECRET_TYPE_BASE_RISK.get(secret_type, 60)
    confidence_mult = CONFIDENCE_MULTIPLIER.get(verification_confidence, CONFIDENCE_MULTIPLIER["unknown"])
    location_bonus = EXPOSURE_LOCATION_BONUS.get(exposure_location, 0)

    score = (base * confidence_mult) + location_bonus
    return _clamp_score(score)


def severity_from_score(score: int) -> SeverityLevel:
    if score >= 90:
        return SeverityLevel.CRITICAL
    if score >= 75:
        return SeverityLevel.HIGH
    if score >= 45:
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW


def build_structured_finding(
    finding_id: str,
    detector: str,
    secret_type: str,
    verification_confidence: str,
    exposure_location: str,
    file_path: str,
    line_number: Optional[int],
    snippet: str,
) -> Dict[str, Any]:
    score = score_finding(secret_type, verification_confidence, exposure_location)
    severity = severity_from_score(score)

    finding = StructuredFinding(
        finding_id=finding_id,
        detector=detector,
        secret_type=secret_type,
        verification_confidence=verification_confidence,
        exposure_location=exposure_location,
        file_path=file_path,
        line_number=line_number,
        snippet=snippet,
        score=score,
        severity=severity,
    )
    return finding.to_dict()
