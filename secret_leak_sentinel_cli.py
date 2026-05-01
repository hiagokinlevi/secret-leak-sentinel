from __future__ import annotations

import json
from collections import Counter
from typing import Any, Iterable

import click


# NOTE:
# This file intentionally keeps logic compact and self-contained for the roadmap task.
# It assumes existing scanner plumbing returns finding dicts with optional severity fields.


def _severity_of(finding: dict[str, Any]) -> str:
    sev = (
        finding.get("severity")
        or finding.get("criticality")
        or finding.get("level")
        or "unknown"
    )
    return str(sev).lower()


def _print_summary(findings: Iterable[dict[str, Any]], exit_code: int) -> None:
    findings_list = list(findings)
    counts = Counter(_severity_of(f) for f in findings_list)

    click.echo("Scan summary")
    click.echo(f"Total findings: {len(findings_list)}")

    # Stable display order for common severities, then any extras.
    ordered = ["critical", "high", "medium", "low", "info", "unknown"]
    for sev in ordered:
        if sev in counts:
            click.echo(f"{sev}: {counts[sev]}")
    for sev in sorted(k for k in counts.keys() if k not in ordered):
        click.echo(f"{sev}: {counts[sev]}")

    click.echo(f"Exit status: {exit_code}")


def _render_console_findings(findings: list[dict[str, Any]], summary_only: bool) -> None:
    if summary_only:
        return
    for finding in findings:
        click.echo(json.dumps(finding, ensure_ascii=False))


@click.group()
def cli() -> None:
    """secret-leak-sentinel CLI."""


# Shared option for scan commands
_summary_only_option = click.option(
    "--summary-only",
    is_flag=True,
    default=False,
    help="Suppress per-finding console lines and print only aggregate summary counts.",
)


@cli.command("scan-path")
@click.argument("path", type=click.Path(exists=True))
@click.option("--json-output", type=click.Path(), default=None)
@click.option("--jsonl-output", type=click.Path(), default=None)
@_summary_only_option
def scan_path(path: str, json_output: str | None, jsonl_output: str | None, summary_only: bool) -> None:
    # Placeholder for existing scanner integration; expected to be replaced by current project logic.
    findings: list[dict[str, Any]] = []

    # Existing behavior: file outputs remain unaffected by --summary-only.
    if json_output:
        with open(json_output, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
    if jsonl_output:
        with open(jsonl_output, "w", encoding="utf-8") as fh:
            for f in findings:
                fh.write(json.dumps(f, ensure_ascii=False) + "\n")

    _render_console_findings(findings, summary_only=summary_only)
    exit_code = 1 if findings else 0
    _print_summary(findings, exit_code=exit_code)
    raise SystemExit(exit_code)


@cli.command("scan-staged")
@click.option("--json-output", type=click.Path(), default=None)
@click.option("--jsonl-output", type=click.Path(), default=None)
@_summary_only_option
def scan_staged(json_output: str | None, jsonl_output: str | None, summary_only: bool) -> None:
    findings: list[dict[str, Any]] = []

    if json_output:
        with open(json_output, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
    if jsonl_output:
        with open(jsonl_output, "w", encoding="utf-8") as fh:
            for f in findings:
                fh.write(json.dumps(f, ensure_ascii=False) + "\n")

    _render_console_findings(findings, summary_only=summary_only)
    exit_code = 1 if findings else 0
    _print_summary(findings, exit_code=exit_code)
    raise SystemExit(exit_code)


@cli.command("scan-git")
@click.option("--json-output", type=click.Path(), default=None)
@click.option("--jsonl-output", type=click.Path(), default=None)
@_summary_only_option
def scan_git(json_output: str | None, jsonl_output: str | None, summary_only: bool) -> None:
    findings: list[dict[str, Any]] = []

    if json_output:
        with open(json_output, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
    if jsonl_output:
        with open(jsonl_output, "w", encoding="utf-8") as fh:
            for f in findings:
                fh.write(json.dumps(f, ensure_ascii=False) + "\n")

    _render_console_findings(findings, summary_only=summary_only)
    exit_code = 1 if findings else 0
    _print_summary(findings, exit_code=exit_code)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    cli()
