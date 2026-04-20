from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


SEVERITY_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _to_uri(path_value: str) -> str:
    p = Path(path_value)
    try:
        return p.as_posix()
    except Exception:
        return str(path_value).replace("\\", "/")


def _rule_id_for_finding(finding: Dict[str, Any]) -> str:
    detector = (
        finding.get("detector")
        or finding.get("detector_name")
        or finding.get("type")
        or "secret-detected"
    )
    normalized = str(detector).strip().lower().replace(" ", "-").replace("_", "-")
    return f"secret-leak-sentinel/{normalized}"


def _level_for_finding(finding: Dict[str, Any]) -> str:
    sev = str(finding.get("severity", "medium")).strip().lower()
    return SEVERITY_LEVEL_MAP.get(sev, "warning")


def _message_for_finding(finding: Dict[str, Any]) -> str:
    if finding.get("message"):
        return str(finding["message"])
    secret_type = finding.get("type") or finding.get("detector") or "Potential secret"
    return f"{secret_type} detected"


def _location_for_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    path = (
        finding.get("path")
        or finding.get("file_path")
        or finding.get("file")
        or "unknown"
    )

    start_line = int(finding.get("line") or finding.get("line_number") or 1)
    start_col = int(finding.get("column") or 1)
    end_line = int(finding.get("end_line") or start_line)
    end_col = int(finding.get("end_column") or start_col)

    return {
        "physicalLocation": {
            "artifactLocation": {"uri": _to_uri(str(path))},
            "region": {
                "startLine": max(1, start_line),
                "startColumn": max(1, start_col),
                "endLine": max(1, end_line),
                "endColumn": max(1, end_col),
            },
        }
    }


def generate_sarif(
    findings: Iterable[Dict[str, Any]],
    *,
    tool_name: str = "secret-leak-sentinel",
    tool_version: Optional[str] = None,
    invocation_command: Optional[str] = None,
) -> Dict[str, Any]:
    findings_list = list(findings)

    rules: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
    results: List[Dict[str, Any]] = []

    for finding in findings_list:
        rule_id = _rule_id_for_finding(finding)
        if rule_id not in rules:
            detector_name = finding.get("detector") or finding.get("type") or "Secret Detector"
            rules[rule_id] = {
                "id": rule_id,
                "name": str(detector_name),
                "shortDescription": {"text": str(detector_name)},
                "fullDescription": {"text": f"Detection rule for {detector_name}"},
                "properties": {
                    "tags": ["security", "secrets", "credential-leak"],
                },
            }

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _level_for_finding(finding),
            "message": {"text": _message_for_finding(finding)},
            "locations": [_location_for_finding(finding)],
        }

        fingerprint = finding.get("fingerprint") or finding.get("id")
        if fingerprint:
            result["partialFingerprints"] = {
                "primaryLocationLineHash": str(fingerprint)
            }

        commit = finding.get("commit") or finding.get("commit_hash")
        if commit:
            result.setdefault("properties", {})["commit"] = str(commit)

        results.append(result)

    driver: Dict[str, Any] = {
        "name": tool_name,
        "informationUri": "https://github.com/",
        "rules": list(rules.values()),
    }
    if tool_version:
        driver["version"] = str(tool_version)

    run: Dict[str, Any] = {
        "tool": {"driver": driver},
        "results": results,
        "invocations": [
            {
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }

    if invocation_command:
        run["invocations"][0]["commandLine"] = invocation_command

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }
