"""
Shannon Entropy Detector
=========================
Identifies high-entropy strings in source files that may represent secrets.

Shannon entropy measures the randomness of a string. Genuine secrets (API keys,
tokens, cryptographic material) tend to have higher entropy than human-readable
text, variable names, or common passwords.

This detector is intentionally broad — it generates more false positives than
regex detection — but catches secrets that don't follow known patterns.

Reference: Shannon, C.E. (1948). "A Mathematical Theory of Communication."

Typical entropy ranges:
  - English prose:         ~3.5 bits/character
  - Base64-encoded random: ~6.0 bits/character
  - Hex-encoded random:    ~4.0 bits/character
  - Password "abc123":     ~2.6 bits/character
  - Random API key:        ~4.5–6.0 bits/character

Default threshold: 4.5 (configurable via ENTROPY_THRESHOLD env var or policy YAML)
"""
import math
import re
from dataclasses import dataclass
from collections import Counter


@dataclass
class EntropyFinding:
    """A high-entropy string detection finding."""
    file_path: str
    line_number: int
    token: str          # The high-entropy token (NOT the surrounding secret value)
    entropy: float      # Calculated Shannon entropy
    masked_excerpt: str # Context around the token, with value masked
    confidence: float   # 0.0 to 1.0 — lower than regex findings due to false positive rate


# Pattern to extract candidate tokens from a line.
# Targets strings that appear in assignment context (right side of = or :)
# and are long enough to plausibly be a secret.
_ASSIGNMENT_VALUE_PATTERN = re.compile(
    r'(?i)(?:key|token|secret|password|passwd|pwd|auth|credential|api)\s*[=:]\s*["\']?([A-Za-z0-9+/=_\-]{20,})["\']?'
)

# Fallback: any standalone long alphanumeric string (may produce more noise)
_STANDALONE_TOKEN_PATTERN = re.compile(r'[A-Za-z0-9+/=]{32,}')


def shannon_entropy(s: str) -> float:
    """
    Calculate the Shannon entropy of a string in bits per character.

    Args:
        s: Input string to analyse.

    Returns:
        Shannon entropy value. Returns 0.0 for empty strings.
    """
    if not s:
        return 0.0

    # Count frequency of each character
    counts = Counter(s)
    length = len(s)

    # H = -sum(p_i * log2(p_i)) where p_i = count_i / total
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )
    return round(entropy, 4)


def _mask_token(token: str) -> str:
    """Return a masked representation of a token, keeping only the first 4 characters."""
    if len(token) <= 4:
        return "****"
    return token[:4] + "****" + f"[{len(token)}chars]"


def scan_content_for_entropy(
    content: str,
    file_path: str,
    threshold: float = 4.5,
    min_length: int = 20,
    use_assignment_context: bool = True,
) -> list[EntropyFinding]:
    """
    Scan file content for high-entropy strings that may represent secrets.

    Args:
        content: Full file content as a string.
        file_path: Path to the file being scanned (used in findings).
        threshold: Minimum Shannon entropy to flag a token (default: 4.5).
        min_length: Minimum string length to consider (default: 20).
        use_assignment_context: If True, only look for tokens in assignment context
                                (reduces false positives). If False, scan all long tokens.

    Returns:
        List of EntropyFinding objects for tokens above the threshold.
    """
    findings: list[EntropyFinding] = []

    for line_no, line in enumerate(content.splitlines(), start=1):
        # Prefer assignment-context extraction to reduce false positives
        if use_assignment_context:
            matches = _ASSIGNMENT_VALUE_PATTERN.finditer(line)
            tokens = [(m.group(1), line) for m in matches if len(m.group(1)) >= min_length]
        else:
            # Fallback to all long strings (noisier)
            tokens = [(m.group(0), line) for m in _STANDALONE_TOKEN_PATTERN.finditer(line)
                      if len(m.group(0)) >= min_length]

        for token, original_line in tokens:
            entropy = shannon_entropy(token)
            if entropy >= threshold:
                # Confidence is lower for entropy-only findings because of false positive risk
                # Longer tokens and higher entropy = higher confidence
                length_factor = min(len(token) / 40, 1.0)  # Normalise to 0-1 for tokens up to 40 chars
                entropy_factor = min((entropy - threshold) / 2.0, 1.0)  # How far above threshold
                confidence = round(0.4 + 0.3 * length_factor + 0.3 * entropy_factor, 2)

                masked = original_line[:original_line.find(token)] + _mask_token(token)

                findings.append(EntropyFinding(
                    file_path=file_path,
                    line_number=line_no,
                    token=_mask_token(token),  # Store only masked token, never the original
                    entropy=entropy,
                    masked_excerpt=masked[:120],
                    confidence=min(confidence, 0.95),  # Cap at 0.95; never claim certainty
                ))

    return findings
