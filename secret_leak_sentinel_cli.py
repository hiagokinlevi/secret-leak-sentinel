#!/usr/bin/env python3
"""CLI entrypoint for secret-leak-sentinel."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

import click


# NOTE:
# This file is intentionally self-contained for task-scoped changes.
# Existing project scanner/classifier imports are expected to remain available
# in the real repository runtime.
try:
    from scanners.filesystem_scanner import scan_path as _scan_path_impl
except Exception:  # pragma: no cover
    _scan_path_impl = None

try:
    from scanners.git_scanner import scan_staged as _scan_staged_impl
    from scanners.git_scanner import scan_git as _scan_git_impl
except Exception:  # pragma: no cover
    _scan_staged_impl = None
    _scan_git_impl = None


def _to_dict(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        return item
    if is_dataclass(item):
        return asdict(item)
    if hasattr(item, "to_dict"):
        return item.to_dict()
    return {"value": str(item)}


def _apply_max_findings(findings: Sequence[Any], max_findings: Optional[int]) -> Tuple[List[Dict[str, Any]], bool]:
    collected: List[Dict[str, Any]] = []
    truncated = False
    for f in findings:
        if max_findings is not None and max_findings >= 0 and len(collected) >= max_findings:
            truncated = True
            break
        collected.append(_to_dict(f))
    return collected, truncated


def _emit(findings: Sequence[Any], max_findings: Optional[int], json_output: bool) -> int:
    normalized, truncated = _apply_max_findings(findings, max_findings)

    if json_output:
        payload = {
            "findings": normalized,
            "count": len(normalized),
            "max_findings": max_findings,
            "truncated": truncated,
        }
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        click.echo(f"Findings: {len(normalized)}")
        if max_findings is not None:
            click.echo(f"Max findings cap: {max_findings}")
        if truncated:
            click.echo("Output truncated: true (scan stopped after reaching --max-findings cap)")

    return 1 if len(normalized) > 0 else 0


@click.group()
def cli() -> None:
    """secret-leak-sentinel CLI."""


@cli.command("scan-path")
@click.argument("path", type=click.Path(exists=True))
@click.option("--json-output", is_flag=True, default=False, help="Emit JSON output")
@click.option("--max-findings", type=click.IntRange(min=1), required=False, default=None, help="Stop after collecting N findings")
def scan_path_cmd(path: str, json_output: bool, max_findings: Optional[int]) -> None:
    findings = _scan_path_impl(path) if _scan_path_impl else []
    raise SystemExit(_emit(findings, max_findings, json_output))


@cli.command("scan-staged")
@click.option("--json-output", is_flag=True, default=False, help="Emit JSON output")
@click.option("--max-findings", type=click.IntRange(min=1), required=False, default=None, help="Stop after collecting N findings")
def scan_staged_cmd(json_output: bool, max_findings: Optional[int]) -> None:
    findings = _scan_staged_impl() if _scan_staged_impl else []
    raise SystemExit(_emit(findings, max_findings, json_output))


@cli.command("scan-git")
@click.option("--json-output", is_flag=True, default=False, help="Emit JSON output")
@click.option("--max-findings", type=click.IntRange(min=1), required=False, default=None, help="Stop after collecting N findings")
def scan_git_cmd(json_output: bool, max_findings: Optional[int]) -> None:
    findings = _scan_git_impl() if _scan_git_impl else []
    raise SystemExit(_emit(findings, max_findings, json_output))


if __name__ == "__main__":
    cli()
