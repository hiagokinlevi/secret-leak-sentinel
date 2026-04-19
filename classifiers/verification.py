from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse


VERIFICATION_VERIFIED = "verified"
VERIFICATION_LIKELY = "likely"
VERIFICATION_UNVERIFIED = "unverified"


@dataclass(frozen=True)
class VerificationResult:
    status: str
    reason: str

    def to_dict(self) -> Dict[str, str]:
        return {"status": self.status, "reason": self.reason}


def _is_hex(value: str, expected_len: Optional[int] = None) -> bool:
    if expected_len is not None and len(value) != expected_len:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]+", value))


def _is_base64url(value: str) -> bool:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value or ""):
        return False
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    try:
        base64.urlsafe_b64decode(padded.encode("utf-8"))
        return True
    except Exception:
        return False


def _verify_jwt(candidate: str) -> VerificationResult:
    parts = candidate.split(".")
    if len(parts) != 3:
        return VerificationResult(VERIFICATION_UNVERIFIED, "jwt-missing-segments")
    if not all(_is_base64url(p) for p in parts if p):
        return VerificationResult(VERIFICATION_UNVERIFIED, "jwt-invalid-base64url")

    try:
        header_padded = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
        payload_padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_padded.encode("utf-8")).decode("utf-8"))
        payload = json.loads(base64.urlsafe_b64decode(payload_padded.encode("utf-8")).decode("utf-8"))
    except Exception:
        return VerificationResult(VERIFICATION_LIKELY, "jwt-structure-valid-json-unreadable")

    alg = str(header.get("alg", "")).upper()
    if alg in {"NONE", ""}:
        return VerificationResult(VERIFICATION_VERIFIED, "jwt-unsigned-or-missing-alg")

    if payload.get("iss") or payload.get("sub") or payload.get("aud"):
        return VerificationResult(VERIFICATION_VERIFIED, "jwt-claims-present")

    return VerificationResult(VERIFICATION_LIKELY, "jwt-structure-valid")


def _verify_aws_access_key_id(candidate: str) -> VerificationResult:
    if re.fullmatch(r"(AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}", candidate or ""):
        return VerificationResult(VERIFICATION_VERIFIED, "aws-access-key-id-format")
    return VerificationResult(VERIFICATION_UNVERIFIED, "aws-access-key-id-format-invalid")


def _verify_github_token(candidate: str) -> VerificationResult:
    # Common GitHub token families with deterministic prefixes and lengths.
    if re.fullmatch(r"gh[pousr]_[A-Za-z0-9_]{20,255}", candidate or ""):
        return VerificationResult(VERIFICATION_VERIFIED, "github-token-prefix-format")
    return VerificationResult(VERIFICATION_UNVERIFIED, "github-token-format-invalid")


def _verify_stripe_key(candidate: str) -> VerificationResult:
    if re.fullmatch(r"(sk|rk)_(live|test)_[A-Za-z0-9]{16,}", candidate or ""):
        env = "live" if "_live_" in candidate else "test"
        return VerificationResult(VERIFICATION_VERIFIED, f"stripe-{env}-key-format")
    return VerificationResult(VERIFICATION_UNVERIFIED, "stripe-key-format-invalid")


def _verify_twilio_token(candidate: str) -> VerificationResult:
    if _is_hex(candidate or "", expected_len=32):
        return VerificationResult(VERIFICATION_VERIFIED, "twilio-auth-token-hex32")
    return VerificationResult(VERIFICATION_UNVERIFIED, "twilio-auth-token-format-invalid")


def _verify_sendgrid_key(candidate: str) -> VerificationResult:
    if re.fullmatch(r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}", candidate or ""):
        return VerificationResult(VERIFICATION_VERIFIED, "sendgrid-token-tripartite")
    return VerificationResult(VERIFICATION_UNVERIFIED, "sendgrid-token-format-invalid")


def _verify_azure_sas_url(candidate: str) -> VerificationResult:
    try:
        parsed = urlparse(candidate)
    except Exception:
        return VerificationResult(VERIFICATION_UNVERIFIED, "azure-sas-url-parse-failed")

    if parsed.scheme not in {"http", "https"}:
        return VerificationResult(VERIFICATION_UNVERIFIED, "azure-sas-url-scheme-invalid")

    query = parse_qs(parsed.query)
    required = {"sig", "se", "sp", "sv"}
    if required.issubset(set(query.keys())):
        return VerificationResult(VERIFICATION_VERIFIED, "azure-sas-required-params-present")
    if {"sig", "se"}.issubset(set(query.keys())):
        return VerificationResult(VERIFICATION_LIKELY, "azure-sas-partial-params-present")
    return VerificationResult(VERIFICATION_UNVERIFIED, "azure-sas-params-missing")


def _verify_vault_token(candidate: str) -> VerificationResult:
    if re.fullmatch(r"hvs\.[A-Za-z0-9]{20,}", candidate or ""):
        return VerificationResult(VERIFICATION_VERIFIED, "vault-service-token-format")
    if re.fullmatch(r"s\.[A-Za-z0-9]{16,}", candidate or ""):
        return VerificationResult(VERIFICATION_LIKELY, "vault-legacy-token-format")
    return VerificationResult(VERIFICATION_UNVERIFIED, "vault-token-format-invalid")


_VERIFIERS = {
    "jwt": _verify_jwt,
    "aws_access_key": _verify_aws_access_key_id,
    "github_token": _verify_github_token,
    "stripe_api_key": _verify_stripe_key,
    "twilio_auth_token": _verify_twilio_token,
    "sendgrid_api_key": _verify_sendgrid_key,
    "azure_sas_url": _verify_azure_sas_url,
    "vault_token": _verify_vault_token,
}


def verify_secret(detector_name: str, candidate: str) -> Dict[str, str]:
    """
    Optional offline verification layer.

    Performs safe, deterministic checks only (format/metadata validation),
    and never makes network/API calls.

    Returns a dictionary with:
      - status: verified | likely | unverified
      - reason: machine-readable explanation
    """
    verifier = _VERIFIERS.get((detector_name or "").strip().lower())
    if not verifier:
        return VerificationResult(
            VERIFICATION_UNVERIFIED,
            "no-verifier-for-detector",
        ).to_dict()

    try:
        return verifier(candidate or "").to_dict()
    except Exception:
        return VerificationResult(
            VERIFICATION_UNVERIFIED,
            "verifier-error",
        ).to_dict()
