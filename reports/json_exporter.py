"""
Exportador JSON de findings
===========================
Converte resultados classificados de varredura em estruturas JSON estáveis,
adequadas para integrações locais como extensões de editor, hooks e pipelines.
"""
from __future__ import annotations

from classifiers.criticality_classifier import ClassifiedFinding


def _severity_summary(classified_findings: list[ClassifiedFinding]) -> dict[str, int]:
    """Retorna a contagem agregada por severidade final."""
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in classified_findings:
        summary[finding.final_criticality.value] = (
            summary.get(finding.final_criticality.value, 0) + 1
        )
    return summary


def classified_finding_to_dict(classified_finding: ClassifiedFinding) -> dict[str, object]:
    """Serializa um finding classificado sem expor o segredo bruto."""
    finding = classified_finding.original_finding
    return {
        "detector_name": finding.detector_name,
        "secret_type": finding.secret_type.value,
        "severity": classified_finding.final_criticality.value,
        "original_severity": finding.criticality.value,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "masked_excerpt": finding.masked_excerpt,
        "confidence": classified_finding.confidence,
        "rationale": classified_finding.rationale,
        "policy_decision": finding.policy_decision,
        "suppressed": finding.suppressed,
        "suppression_reason": finding.suppression_reason,
        "entropy_corroboration": classified_finding.entropy_corroboration,
        "cross_file_corroboration": classified_finding.cross_file_corroboration,
        "correlated_file_count": classified_finding.correlated_file_count,
        "context_penalty": classified_finding.context_penalty,
        "context_escalation": classified_finding.context_escalation,
        "context_labels": list(classified_finding.context_labels),
    }


def build_scan_file_payload(
    classified_findings: list[ClassifiedFinding],
    scan_target: str,
    patch_mode: bool,
    policy_profile: str,
    entropy_enabled: bool,
    entropy_threshold: float,
) -> dict[str, object]:
    """Monta o payload JSON de uma execução de `scan-file`."""
    return {
        "scan_target": scan_target,
        "scan_mode": "patch" if patch_mode else "file",
        "policy_profile": policy_profile,
        "entropy_enabled": entropy_enabled,
        "entropy_threshold": entropy_threshold,
        "total_findings": len(classified_findings),
        "summary": _severity_summary(classified_findings),
        "findings": [
            classified_finding_to_dict(classified_finding)
            for classified_finding in classified_findings
        ],
    }
