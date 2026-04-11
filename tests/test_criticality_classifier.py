from classifiers.criticality_classifier import classify_finding
from detectors.regex_detector import Criticality, Finding, SecretType


def _finding(
    *,
    file_path: str,
    criticality: Criticality = Criticality.HIGH,
    confidence: float = 0.65,
) -> Finding:
    return Finding(
        detector_name="generic_api_key_assignment",
        secret_type=SecretType.API_TOKEN,
        criticality=criticality,
        file_path=file_path,
        line_number=3,
        masked_excerpt="api_****",
        confidence=confidence,
    )


def test_dotenv_variant_escalates_high_severity_to_critical() -> None:
    classified = classify_finding(_finding(file_path=".env.production"))

    assert classified.final_criticality == Criticality.CRITICAL
    assert classified.context_escalation is True
    assert "live_secret_store" in classified.context_labels
    assert "High-risk file context (.env.production)" in classified.rationale


def test_named_env_file_remains_high_risk() -> None:
    classified = classify_finding(_finding(file_path="deploy/config.env"))

    assert classified.final_criticality == Criticality.CRITICAL
    assert classified.context_escalation is True


def test_dotenv_example_placeholder_does_not_escalate() -> None:
    classified = classify_finding(_finding(file_path=".env.example"))

    assert classified.final_criticality == Criticality.HIGH
    assert classified.context_escalation is False


def test_dotenv_placeholder_in_sample_context_is_penalized() -> None:
    classified = classify_finding(
        _finding(file_path="docs/examples/.env.sample", criticality=Criticality.CRITICAL, confidence=0.85)
    )

    assert classified.final_criticality == Criticality.HIGH
    assert classified.context_penalty is True
    assert classified.context_escalation is False
    assert "sample_or_test" in classified.context_labels


def test_documentation_yaml_context_reduces_confidence() -> None:
    classified = classify_finding(_finding(file_path="docs/runbooks/incident-response.yml"))

    assert classified.context_penalty is True
    assert classified.confidence < 0.65
    assert "documentation_path" in classified.context_labels
    assert "Documentation-oriented path context" in classified.rationale


def test_ci_pipeline_context_boosts_confidence_without_severity_jump() -> None:
    classified = classify_finding(_finding(file_path=".github/workflows/release.yml"))

    assert classified.final_criticality == Criticality.HIGH
    assert classified.context_escalation is True
    assert classified.confidence > 0.65
    assert "ci_pipeline" in classified.context_labels
    assert "CI pipeline context" in classified.rationale
