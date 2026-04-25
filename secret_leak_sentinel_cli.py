#!/usr/bin/env python3
import hashlib
import json
from copy import deepcopy

import click


@click.group()
def cli():
    """secret-leak-sentinel CLI."""
    pass


def _redact_value(value: str) -> str:
    if not isinstance(value, str) or not value:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    if len(value) <= 6:
        return f"***#{digest}"
    return f"{value[:3]}***{value[-2:]}#{digest}"


def _apply_redaction_to_findings(payload):
    redacted = deepcopy(payload)
    findings = redacted.get("findings", []) if isinstance(redacted, dict) else []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if "match" in finding:
            finding["match"] = _redact_value(finding.get("match"))
        if "secret" in finding:
            finding["secret"] = _redact_value(finding.get("secret"))
        if "value" in finding:
            finding["value"] = _redact_value(finding.get("value"))
    return redacted


def _emit_machine_output(report: dict, json_output: str = None, jsonl_output: str = None, redact_secrets: bool = False):
    machine_report = _apply_redaction_to_findings(report) if redact_secrets else report

    if json_output:
        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(machine_report, f, indent=2)

    if jsonl_output:
        with open(jsonl_output, "w", encoding="utf-8") as f:
            for finding in machine_report.get("findings", []):
                f.write(json.dumps(finding) + "\n")


@cli.command("scan-path")
@click.argument("path", type=click.Path(exists=False))
@click.option("--json-output", type=click.Path(), default=None, help="Write scan report as JSON.")
@click.option("--jsonl-output", type=click.Path(), default=None, help="Write findings as JSONL.")
@click.option(
    "--redact-secrets",
    is_flag=True,
    default=False,
    help="Mask raw matched secret values in JSON/JSONL outputs using deterministic redaction.",
)
def scan_path(path, json_output, jsonl_output, redact_secrets):
    """Scan a filesystem path for secrets."""
    # Placeholder for existing scanner integration.
    report = {
        "path": path,
        "findings": [],
        "summary": {"total_findings": 0},
    }
    _emit_machine_output(
        report,
        json_output=json_output,
        jsonl_output=jsonl_output,
        redact_secrets=redact_secrets,
    )


@cli.command("scan-staged")
@click.option("--json-output", type=click.Path(), default=None, help="Write scan report as JSON.")
@click.option("--jsonl-output", type=click.Path(), default=None, help="Write findings as JSONL.")
@click.option(
    "--redact-secrets",
    is_flag=True,
    default=False,
    help="Mask raw matched secret values in JSON/JSONL outputs using deterministic redaction.",
)
def scan_staged(json_output, jsonl_output, redact_secrets):
    """Scan staged git changes for secrets."""
    report = {"findings": [], "summary": {"total_findings": 0}}
    _emit_machine_output(
        report,
        json_output=json_output,
        jsonl_output=jsonl_output,
        redact_secrets=redact_secrets,
    )


@cli.command("scan-git")
@click.option("--json-output", type=click.Path(), default=None, help="Write scan report as JSON.")
@click.option("--jsonl-output", type=click.Path(), default=None, help="Write findings as JSONL.")
@click.option(
    "--redact-secrets",
    is_flag=True,
    default=False,
    help="Mask raw matched secret values in JSON/JSONL outputs using deterministic redaction.",
)
def scan_git(json_output, jsonl_output, redact_secrets):
    """Scan git history for secrets."""
    report = {"findings": [], "summary": {"total_findings": 0}}
    _emit_machine_output(
        report,
        json_output=json_output,
        jsonl_output=jsonl_output,
        redact_secrets=redact_secrets,
    )


if __name__ == "__main__":
    cli()
