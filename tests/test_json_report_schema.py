import hashlib


def _normalize_match_context(value: str) -> str:
    """Mirror production normalization expectations for fingerprint stability tests."""
    return " ".join((value or "").strip().split()).lower()


def _expected_fingerprint(value: str) -> str:
    return hashlib.sha256(_normalize_match_context(value).encode("utf-8")).hexdigest()


def test_json_findings_include_rule_id_and_fingerprint(scan_file_json):
    """Structured JSON findings should expose stable dedupe fields."""
    payload = scan_file_json("tests/fixtures/secrets/aws_key.txt")
    findings = payload.get("findings", [])
    assert findings, "expected at least one finding in aws_key fixture"

    finding = findings[0]
    assert "rule_id" in finding, "json finding must include rule_id"
    assert isinstance(finding["rule_id"], str) and finding["rule_id"].strip()

    assert "fingerprint" in finding, "json finding must include fingerprint"
    assert isinstance(finding["fingerprint"], str) and len(finding["fingerprint"]) == 64


def test_json_fingerprint_is_normalized_context_hash(scan_file_json):
    """Fingerprint should be sha256 hash of normalized match context for stability."""
    payload = scan_file_json("tests/fixtures/secrets/aws_key.txt")
    findings = payload.get("findings", [])
    assert findings, "expected at least one finding in aws_key fixture"

    finding = findings[0]

    # Backward-compatible with existing payloads that may expose either context or snippet-like fields.
    context = (
        finding.get("match_context")
        or finding.get("snippet")
        or finding.get("match")
        or ""
    )
    assert context, "expected finding to include match context/snippet for fingerprint derivation"

    assert finding["fingerprint"] == _expected_fingerprint(context)
