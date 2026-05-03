from __future__ import annotations

import json
from collections import OrderedDict
from typing import Any, Dict, Iterable, List


_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _normalize_severity(value: Any) -> str:
    if value is None:
        return "low"
    return str(value).strip().lower() or "low"


def _to_int(value: Any, default: int = 1) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _rule_id_for_finding(finding: Dict[str, Any]) -> str:
    return (
        finding.get("rule_id")
        or finding.get("detector_id")
        or finding.get("type")
        or finding.get("category")
        or "secret-leak"
    )


def _message_for_finding(finding: Dict[str, Any]) -> str:
    return (
        finding.get("message")
        or finding.get("description")
        or finding.get("summary")
        or "Potential secret detected"
    )


def _build_sarif(findings: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    findings_list = list(findings or [])

    rules: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
    results: List[Dict[str, Any]] = []

    for finding in findings_list:
        rule_id = str(_rule_id_for_finding(finding))
        severity = _normalize_severity(finding.get("severity"))
        level = _SEVERITY_TO_LEVEL.get(severity, "warning")

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": rule_id},
                "properties": {"severity": severity},
            }

        file_path = finding.get("file_path") or finding.get("path") or finding.get("filename") or ""
        line = _to_int(finding.get("line") or finding.get("line_number"), default=1)
        column = _to_int(finding.get("column") or finding.get("col"), default=1)

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": _message_for_finding(finding)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {"startLine": line, "startColumn": column},
                    }
                }
            ],
        }

        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secret-leak-sentinel",
                        "informationUri": "https://github.com/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def generate_report(findings: Iterable[Dict[str, Any]], output_format: str = "markdown") -> str:
    fmt = (output_format or "markdown").strip().lower()

    if fmt == "json":
        return json.dumps(list(findings or []), indent=2)

    if fmt == "sarif":
        return json.dumps(_build_sarif(findings), indent=2)

    # markdown (default)
    rows = ["# Secret Leak Sentinel Report", "", "## Findings", ""]
    findings_list = list(findings or [])
    if not findings_list:
        rows.append("No findings detected.")
        return "\n".join(rows)

    for idx, finding in enumerate(findings_list, start=1):
        rows.append(f"### {idx}. {_message_for_finding(finding)}")
        rows.append(f"- Rule: `{_rule_id_for_finding(finding)}`")
        rows.append(f"- Severity: `{_normalize_severity(finding.get('severity'))}`")
        path = finding.get("file_path") or finding.get("path") or ""
        line = finding.get("line") or finding.get("line_number") or ""
        col = finding.get("column") or finding.get("col") or ""
        rows.append(f"- Location: `{path}:{line}:{col}`")
        rows.append("")

    return "\n".join(rows)
