from schemas.finding_schema import (
    build_structured_finding,
    score_finding,
    severity_from_score,
    SeverityLevel,
)


def test_score_finding_expected_ordering():
    critical_like = score_finding("private_key", "confirmed", "public_repo")
    moderate_like = score_finding("generic_password", "medium", "working_tree")
    low_like = score_finding("high_entropy_string", "low", "docs_example")

    assert critical_like > moderate_like > low_like


def test_severity_thresholds():
    assert severity_from_score(95) == SeverityLevel.CRITICAL
    assert severity_from_score(80) == SeverityLevel.HIGH
    assert severity_from_score(50) == SeverityLevel.MEDIUM
    assert severity_from_score(20) == SeverityLevel.LOW


def test_build_structured_finding_machine_readable_shape():
    finding = build_structured_finding(
        finding_id="f-001",
        detector="regex.aws_access_key",
        secret_type="cloud_api_key",
        verification_confidence="high",
        exposure_location="git_history",
        file_path="src/config.py",
        line_number=12,
        snippet="AWS_SECRET_ACCESS_KEY=***",
    )

    assert finding["finding_id"] == "f-001"
    assert finding["detector"] == "regex.aws_access_key"
    assert finding["severity"] in {"low", "medium", "high", "critical"}
    assert isinstance(finding["score"], int)
    assert 0 <= finding["score"] <= 100
