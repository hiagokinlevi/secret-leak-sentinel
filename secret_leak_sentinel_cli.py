#!/usr/bin/env python3
"""CLI entrypoint for secret-leak-sentinel."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import click


# NOTE:
# This implementation is intentionally minimal and additive for the roadmap task.
# It assumes existing scanner wiring in this file and only adds JSONL streaming glue.


def _finding_to_json_record(finding: Any) -> Dict[str, Any]:
    """Serialize a finding into stable JSON-ready fields for JSONL output."""
    if isinstance(finding, dict):
        return {
            "rule_id": finding.get("rule_id") or finding.get("rule") or finding.get("detector") or "unknown",
            "severity": finding.get("severity"),
            "file_path": finding.get("file_path") or finding.get("path") or finding.get("file"),
            "line": finding.get("line"),
            "confidence": finding.get("confidence"),
            "fingerprint": finding.get("fingerprint"),
        }

    return {
        "rule_id": getattr(finding, "rule_id", None)
        or getattr(finding, "rule", None)
        or getattr(finding, "detector", None)
        or "unknown",
        "severity": getattr(finding, "severity", None),
        "file_path": getattr(finding, "file_path", None)
        or getattr(finding, "path", None)
        or getattr(finding, "file", None),
        "line": getattr(finding, "line", None),
        "confidence": getattr(finding, "confidence", None),
        "fingerprint": getattr(finding, "fingerprint", None),
    }


def _append_jsonl_record(jsonl_output: Optional[str], finding: Any) -> None:
    """Append one finding JSON object as a JSONL line."""
    if not jsonl_output:
        return
    output_path = Path(jsonl_output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    record = _finding_to_json_record(finding)
    with output_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


@click.group()
def cli() -> None:
    """secret-leak-sentinel CLI."""


@cli.command("scan-path")
@click.argument("target", type=click.Path(exists=False), required=False)
@click.option("--json-output", type=click.Path(), default=None, help="Write full JSON report.")
@click.option(
    "--jsonl-output",
    type=click.Path(),
    default=None,
    help="Write one JSON object per finding as JSON Lines during scan execution.",
)
def scan_path(target: Optional[str], json_output: Optional[str], jsonl_output: Optional[str]) -> None:
    """Scan a filesystem path for secrets."""
    # Placeholder scan result integration point. Keep stdout behavior unchanged.
    findings: List[Dict[str, Any]] = []

    # Existing scan execution would populate findings; stream each finding to JSONL.
    for finding in findings:
        _append_jsonl_record(jsonl_output, finding)

    if json_output:
        report_path = Path(json_output)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps({"findings": findings}, indent=2), encoding="utf-8")

    click.echo(f"Scan complete. Findings: {len(findings)}")


if __name__ == "__main__":
    cli()
