from __future__ import annotations

import copy
import json
from typing import Any, Dict, Iterable, List

REDACTION_MASK = "***REDACTED***"
REDACTABLE_KEYS = {
    "secret",
    "secret_value",
    "matched",
    "match",
    "value",
    "raw",
    "raw_value",
    "token",
    "credential",
    "snippet",
    "evidence",
}


def _redact_obj(obj: Any, mask: str = REDACTION_MASK) -> Any:
    if isinstance(obj, dict):
        redacted: Dict[str, Any] = {}
        for key, value in obj.items():
            if isinstance(key, str) and key.lower() in REDACTABLE_KEYS and isinstance(value, str):
                redacted[key] = mask
            else:
                redacted[key] = _redact_obj(value, mask=mask)
        return redacted
    if isinstance(obj, list):
        return [_redact_obj(item, mask=mask) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_redact_obj(item, mask=mask) for item in obj)
    return obj


def serialize_json_report(report: Dict[str, Any], redact_findings: bool = False) -> str:
    payload = copy.deepcopy(report)
    if redact_findings:
        payload = _redact_obj(payload)
    return json.dumps(payload, indent=2, sort_keys=True)


def serialize_markdown_report(findings: Iterable[Dict[str, Any]], redact_findings: bool = False) -> str:
    rows: List[Dict[str, Any]] = list(copy.deepcopy(list(findings)))
    if redact_findings:
        rows = _redact_obj(rows)

    lines: List[str] = ["# Secret Leak Sentinel Report", ""]
    if not rows:
        lines.append("✅ No findings detected.")
        return "\n".join(lines) + "\n"

    lines.extend([
        "| Detector | Severity | File | Line | Finding |",
        "|---|---|---|---:|---|",
    ])

    for finding in rows:
        detector = str(finding.get("detector", ""))
        severity = str(finding.get("severity", ""))
        file_path = str(finding.get("file_path", finding.get("path", "")))
        line = str(finding.get("line", finding.get("line_number", "")))
        finding_text = str(
            finding.get("matched")
            or finding.get("secret")
            or finding.get("value")
            or finding.get("snippet")
            or ""
        )
        lines.append(f"| {detector} | {severity} | {file_path} | {line} | {finding_text} |")

    return "\n".join(lines) + "\n"
