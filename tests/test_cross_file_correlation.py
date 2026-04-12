from classifiers.criticality_classifier import classify_all
from classifiers.cross_file_correlation import correlate_entropy_findings
from detectors.entropy_detector import EntropyFinding
from detectors.regex_detector import Criticality, Finding, SecretType


def _entropy(
    file_path: str,
    line_number: int,
    fingerprint: str = "shared-fingerprint",
    token: str = "aB3x****[36chars]",
) -> EntropyFinding:
    return EntropyFinding(
        file_path=file_path,
        line_number=line_number,
        token=token,
        entropy=5.12,
        masked_excerpt='api_key = "aB3x****[36chars]"',
        confidence=0.74,
        token_fingerprint=fingerprint,
    )


def test_correlate_entropy_findings_requires_distinct_files() -> None:
    correlations = correlate_entropy_findings(
        [
            _entropy("src/a.py", 3),
            _entropy("src/a.py", 9),
        ]
    )

    assert correlations == []


def test_correlate_entropy_findings_groups_reused_token_across_files() -> None:
    correlations = correlate_entropy_findings(
        [
            _entropy("src/a.py", 3),
            _entropy("src/b.py", 8),
        ]
    )

    assert len(correlations) == 1
    assert correlations[0].distinct_file_count == 2
    assert correlations[0].occurrence_count == 2
    assert correlations[0].file_paths == ("src/a.py", "src/b.py")


def test_classify_all_promotes_entropy_only_reuse_to_high() -> None:
    classified = classify_all(
        regex_findings=[],
        entropy_findings=[
            _entropy("src/a.py", 3),
            _entropy("src/b.py", 8),
        ],
    )

    assert len(classified) == 2
    assert all(item.original_finding.detector_name == "cross_file_entropy_reuse" for item in classified)
    assert all(item.final_criticality == Criticality.HIGH for item in classified)
    assert all("Cross-file entropy correlation confirmed" in item.rationale for item in classified)


def test_classify_all_enhances_existing_regex_finding_without_duplicate() -> None:
    regex_finding = Finding(
        detector_name="generic_secret_assignment",
        secret_type=SecretType.GENERIC_SECRET,
        criticality=Criticality.MEDIUM,
        file_path="src/a.py",
        line_number=3,
        masked_excerpt='secret = "aB3x****[36chars]"',
        confidence=0.65,
    )

    classified = classify_all(
        regex_findings=[regex_finding],
        entropy_findings=[
            _entropy("src/a.py", 3),
            _entropy("src/b.py", 8),
        ],
    )

    assert len(classified) == 2

    a_py_findings = [
        item for item in classified
        if item.original_finding.file_path == "src/a.py"
    ]
    assert len(a_py_findings) == 1
    assert a_py_findings[0].final_criticality == Criticality.HIGH
    assert "Cross-file entropy correlation confirmed" in a_py_findings[0].rationale

    b_py_findings = [
        item for item in classified
        if item.original_finding.file_path == "src/b.py"
    ]
    assert len(b_py_findings) == 1
    assert b_py_findings[0].original_finding.detector_name == "cross_file_entropy_reuse"
