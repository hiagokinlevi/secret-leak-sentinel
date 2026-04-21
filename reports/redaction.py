from __future__ import annotations

from typing import Any


_DEFAULT_KEEP_TAIL = 4
_DEFAULT_MASK = "********"


def _looks_like_secret(value: str) -> bool:
    """Heuristic guard to avoid over-redacting short/non-secret strings.

    This utility is intended for report safety, not primary detection.
    It redacts values that are plausibly secret-like (long-ish and token-like).
    """
    if not value:
        return False
    if len(value) < 8:
        return False

    # Common token-ish characteristics
    has_separator = any(sep in value for sep in ("_", "-", ".", "="))
    mixed_charset = any(c.isalpha() for c in value) and any(c.isdigit() for c in value)
    long_dense = len(value) >= 20

    return has_separator or mixed_charset or long_dense


def redact_secret_value(value: str, keep_tail: int = _DEFAULT_KEEP_TAIL) -> str:
    """Mask a secret value to a safe report format.

    Example:
      sk_live_1234567890abcd -> sk_live_********abcd

    Strategy:
      - Preserve a semantic prefix when possible (up to final underscore/hyphen boundary)
      - Preserve last `keep_tail` characters
      - Replace middle with fixed mask token
    """
    if not isinstance(value, str):
        return value  # type: ignore[return-value]

    if not value:
        return value

    tail = value[-keep_tail:] if len(value) > keep_tail else value

    # Prefer stable provider prefix like "sk_live_", "ghp_", etc.
    pivot = max(value.rfind("_"), value.rfind("-"))
    if 0 <= pivot < len(value) - 1:
        prefix = value[: pivot + 1]
    else:
        # Fallback to first 4 chars for unknown formats
        prefix = value[:4] if len(value) > keep_tail else ""

    if len(value) <= keep_tail + len(prefix):
        # Very short strings: just mask entire content footprint
        return f"{prefix}{_DEFAULT_MASK}"

    return f"{prefix}{_DEFAULT_MASK}{tail}"


def redact_for_report(payload: Any) -> Any:
    """Recursively redact probable secret strings inside report payloads.

    Use this on report dictionaries/lists immediately before markdown/json serialization.
    """
    if isinstance(payload, dict):
        return {k: redact_for_report(v) for k, v in payload.items()}

    if isinstance(payload, list):
        return [redact_for_report(v) for v in payload]

    if isinstance(payload, tuple):
        return tuple(redact_for_report(v) for v in payload)

    if isinstance(payload, str):
        if _looks_like_secret(payload):
            return redact_secret_value(payload)
        return payload

    return payload
