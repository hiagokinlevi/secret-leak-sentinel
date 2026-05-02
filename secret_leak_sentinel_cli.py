from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click

from cli.app import cli
from cli.commands.scan_git import scan_git as _scan_git
from cli.commands.scan_path import scan_path as _scan_path
from cli.commands.scan_staged import scan_staged as _scan_staged


_SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _finding_severity(finding: dict) -> str:
    sev = (
        finding.get("severity")
        or finding.get("classification", {}).get("severity")
        or "low"
    )
    return str(sev).lower()


def _should_fail(findings: list[dict], threshold: Optional[str]) -> bool:
    if not threshold:
        return False
    t = _SEVERITY_ORDER[threshold]
    for f in findings:
        if _SEVERITY_ORDER.get(_finding_severity(f), 0) >= t:
            return True
    return False


def _extract_findings(result) -> list[dict]:
    if result is None:
        return []
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        if isinstance(result.get("findings"), list):
            return result["findings"]
    return []


def _gate_and_exit(result, fail_on_severity: Optional[str]):
    findings = _extract_findings(result)
    if _should_fail(findings, fail_on_severity):
        click.echo(
            f"Failing due to finding(s) at or above severity '{fail_on_severity}'.",
            err=True,
        )
        raise SystemExit(2)


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx):
    if ctx.invoked_subcommand is None:
        cli.main(args=["--help"], standalone_mode=False)


@main.command("scan-path")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--fail-on-severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Exit non-zero when findings at/above this severity exist.",
)
@click.pass_context
def scan_path_cmd(ctx, path: Path, fail_on_severity: Optional[str]):
    result = _scan_path.main(
        args=[str(path)],
        standalone_mode=False,
    )
    _gate_and_exit(result, fail_on_severity.lower() if fail_on_severity else None)


@main.command("scan-staged")
@click.option(
    "--fail-on-severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Exit non-zero when findings at/above this severity exist.",
)
@click.pass_context
def scan_staged_cmd(ctx, fail_on_severity: Optional[str]):
    result = _scan_staged.main(args=[], standalone_mode=False)
    _gate_and_exit(result, fail_on_severity.lower() if fail_on_severity else None)


@main.command("scan-git")
@click.option(
    "--fail-on-severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Exit non-zero when findings at/above this severity exist.",
)
@click.pass_context
def scan_git_cmd(ctx, fail_on_severity: Optional[str]):
    result = _scan_git.main(args=[], standalone_mode=False)
    _gate_and_exit(result, fail_on_severity.lower() if fail_on_severity else None)


if __name__ == "__main__":
    try:
        main()
    except SystemExit as exc:
        raise
