from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import click

from scanners.filesystem_scanner import scan_path as scanner_scan_path
from scanners.git_scanner import scan_git_history, scan_staged_changes


MASK_TOKENS = ("***", "[REDACTED]", "<redacted>", "(redacted)")


def _looks_unmasked(value: Any) -> bool:
    if value is None:
        return False
    text = str(value)
    if not text:
        return False
    # If it contains strong secret-like material and no masking token, treat as unmasked.
    secret_like = [
        r"AKIA[0-9A-Z]{16}",
        r"ghp_[A-Za-z0-9]{20,}",
        r"sk_live_[A-Za-z0-9]{16,}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"(?i)(password|token|secret|api[_-]?key)\s*[:=]\s*[^\s]{6,}",
    ]
    if not any(re.search(p, text) for p in secret_like):
        return False
    return not any(tok in text for tok in MASK_TOKENS)


def _iter_strings(obj: Any):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_strings(v)
    elif isinstance(obj, (str, int, float, bool)):
        yield str(obj)


def _enforce_masked_only(payload: dict[str, Any], fail_on_unmasked: bool) -> None:
    if not fail_on_unmasked:
        return
    for s in _iter_strings(payload):
        if _looks_unmasked(s):
            raise click.ClickException(
                "Unmasked secret-like material detected in output payload while --fail-on-unmasked is enabled."
            )


def _scan_common_options(fn):
    fn = click.option("--json-output", "json_output", type=click.Path(dir_okay=False, path_type=Path), default=None)(fn)
    fn = click.option("--fail-on-unmasked", is_flag=True, default=False, help="Exit non-zero if any output payload appears to contain unmasked secret material.")(fn)
    return fn


@click.group()
def cli() -> None:
    """secret-leak-sentinel CLI."""


@cli.command("scan-path")
@click.argument("target", type=click.Path(exists=True, file_okay=False, path_type=Path))
@_scan_common_options
def scan_path_cmd(target: Path, json_output: Path | None, fail_on_unmasked: bool) -> None:
    findings = scanner_scan_path(str(target))
    payload = {"target": str(target), "findings": findings, "count": len(findings)}
    _enforce_masked_only(payload, fail_on_unmasked)
    if json_output:
        json_output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    click.echo(json.dumps(payload, indent=2))
    raise SystemExit(1 if findings else 0)


@cli.command("scan-staged")
@_scan_common_options
def scan_staged_cmd(json_output: Path | None, fail_on_unmasked: bool) -> None:
    findings = scan_staged_changes()
    payload = {"mode": "staged", "findings": findings, "count": len(findings)}
    _enforce_masked_only(payload, fail_on_unmasked)
    if json_output:
        json_output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    click.echo(json.dumps(payload, indent=2))
    raise SystemExit(1 if findings else 0)


@cli.command("scan-git")
@click.option("--max-commits", type=int, default=100, show_default=True)
@_scan_common_options
def scan_git_cmd(max_commits: int, json_output: Path | None, fail_on_unmasked: bool) -> None:
    findings = scan_git_history(max_commits=max_commits)
    payload = {"mode": "git-history", "max_commits": max_commits, "findings": findings, "count": len(findings)}
    _enforce_masked_only(payload, fail_on_unmasked)
    if json_output:
        json_output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    click.echo(json.dumps(payload, indent=2))
    raise SystemExit(1 if findings else 0)


if __name__ == "__main__":
    cli()
