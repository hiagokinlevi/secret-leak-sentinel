from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

import click

from scanners.path_scanner import scan_path as scanner_scan_path
from scanners.git_scanner import scan_staged as scanner_scan_staged
from scanners.git_scanner import scan_git as scanner_scan_git


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _normalize_severity(value: str | None) -> str:
    if not value:
        return "info"
    normalized = str(value).strip().lower()
    if normalized not in SEVERITY_ORDER:
        return "info"
    return normalized


def _highest_finding_severity(findings: Iterable[dict[str, Any]]) -> str:
    highest = "info"
    highest_score = SEVERITY_ORDER[highest]
    for finding in findings or []:
        sev = _normalize_severity(finding.get("severity"))
        score = SEVERITY_ORDER[sev]
        if score > highest_score:
            highest = sev
            highest_score = score
    return highest


def _exit_code_for_threshold(findings: list[dict[str, Any]], threshold: str | None) -> int:
    threshold_norm = _normalize_severity(threshold)
    highest = _highest_finding_severity(findings)
    return 1 if SEVERITY_ORDER[highest] >= SEVERITY_ORDER[threshold_norm] and findings else 0


def _emit_output(findings: list[dict[str, Any]], json_output: bool) -> None:
    if json_output:
        click.echo(json.dumps({"findings": findings}, indent=2))
    else:
        for f in findings:
            click.echo(f"[{_normalize_severity(f.get('severity')).upper()}] {f.get('file', '<unknown>')}:{f.get('line', '?')} {f.get('message', '')}")


@click.group()
def cli() -> None:
    pass


@click.command("scan-path")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--json-output", is_flag=True, default=False)
@click.option(
    "--exit-code-threshold",
    type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False),
    default="info",
    show_default=True,
    help="Exit non-zero when the highest finding severity is at or above this level.",
)
def scan_path_cmd(path: Path, json_output: bool, exit_code_threshold: str) -> None:
    findings = scanner_scan_path(path)
    _emit_output(findings, json_output)
    raise SystemExit(_exit_code_for_threshold(findings, exit_code_threshold))


@click.command("scan-staged")
@click.option("--json-output", is_flag=True, default=False)
@click.option(
    "--exit-code-threshold",
    type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False),
    default="info",
    show_default=True,
    help="Exit non-zero when the highest finding severity is at or above this level.",
)
def scan_staged_cmd(json_output: bool, exit_code_threshold: str) -> None:
    findings = scanner_scan_staged()
    _emit_output(findings, json_output)
    raise SystemExit(_exit_code_for_threshold(findings, exit_code_threshold))


@click.command("scan-git")
@click.option("--json-output", is_flag=True, default=False)
@click.option(
    "--exit-code-threshold",
    type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False),
    default="info",
    show_default=True,
    help="Exit non-zero when the highest finding severity is at or above this level.",
)
def scan_git_cmd(json_output: bool, exit_code_threshold: str) -> None:
    findings = scanner_scan_git()
    _emit_output(findings, json_output)
    raise SystemExit(_exit_code_for_threshold(findings, exit_code_threshold))


cli.add_command(scan_path_cmd)
cli.add_command(scan_staged_cmd)
cli.add_command(scan_git_cmd)


if __name__ == "__main__":
    cli()
