from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

from scanners.filesystem_scanner import scan_path as scanner_scan_path
from scanners.git_scanner import scan_git_history, scan_staged_files
from reports.markdown_report import generate_markdown_report


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def min_severity_option(func):
    return click.option(
        "--min-severity",
        type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
        default="low",
        show_default=True,
        help="Only emit findings at or above this severity.",
    )(func)


def _normalize_severity(value: Optional[str]) -> str:
    if not value:
        return "low"
    return str(value).strip().lower()


def _passes_min_severity(finding: Dict[str, Any], min_severity: str) -> bool:
    threshold = SEVERITY_ORDER.get(_normalize_severity(min_severity), 0)
    sev = _normalize_severity(finding.get("severity"))
    rank = SEVERITY_ORDER.get(sev, 0)
    return rank >= threshold


def _apply_min_severity(findings: List[Dict[str, Any]], min_severity: str) -> List[Dict[str, Any]]:
    return [f for f in findings if _passes_min_severity(f, min_severity)]


def _emit_results(findings: List[Dict[str, Any]], json_output: Optional[str], report: Optional[str]) -> None:
    if json_output:
        Path(json_output).write_text(json.dumps(findings, indent=2), encoding="utf-8")

    if report:
        markdown = generate_markdown_report(findings)
        Path(report).write_text(markdown, encoding="utf-8")

    click.echo(json.dumps(findings, indent=2))


@click.group()
def cli() -> None:
    pass


@cli.command("scan-path")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--json-output", type=click.Path(path_type=Path), default=None)
@click.option("--report", type=click.Path(path_type=Path), default=None)
@min_severity_option
def scan_path_cmd(path: Path, json_output: Optional[Path], report: Optional[Path], min_severity: str) -> None:
    findings = scanner_scan_path(path)
    findings = _apply_min_severity(findings, min_severity)
    _emit_results(findings, str(json_output) if json_output else None, str(report) if report else None)


@cli.command("scan-staged")
@click.option("--json-output", type=click.Path(path_type=Path), default=None)
@click.option("--report", type=click.Path(path_type=Path), default=None)
@min_severity_option
def scan_staged_cmd(json_output: Optional[Path], report: Optional[Path], min_severity: str) -> None:
    findings = scan_staged_files()
    findings = _apply_min_severity(findings, min_severity)
    _emit_results(findings, str(json_output) if json_output else None, str(report) if report else None)


@cli.command("scan-git")
@click.option("--json-output", type=click.Path(path_type=Path), default=None)
@click.option("--report", type=click.Path(path_type=Path), default=None)
@min_severity_option
def scan_git_cmd(json_output: Optional[Path], report: Optional[Path], min_severity: str) -> None:
    findings = scan_git_history()
    findings = _apply_min_severity(findings, min_severity)
    _emit_results(findings, str(json_output) if json_output else None, str(report) if report else None)


if __name__ == "__main__":
    cli()
