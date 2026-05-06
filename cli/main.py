from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click

from reports.markdown import generate_markdown_report
from scanners.diff_scanner import scan_unified_diff


@click.group()
def cli() -> None:
    """secret-leak-sentinel CLI."""


@cli.command("scan-diff")
@click.option(
    "--patch-file",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
    default=None,
    help="Path to unified diff patch file. Defaults to stdin when omitted.",
)
@click.option("--json-output", type=click.Path(path_type=Path), default=None, help="Write findings as JSON.")
@click.option("--markdown-output", type=click.Path(path_type=Path), default=None, help="Write findings as Markdown.")
def scan_diff_command(
    patch_file: Optional[Path],
    json_output: Optional[Path],
    markdown_output: Optional[Path],
) -> None:
    """Scan only added/modified lines from a unified diff for secrets."""

    if patch_file is None:
        patch_text = click.get_text_stream("stdin").read()
    else:
        patch_text = patch_file.read_text(encoding="utf-8", errors="replace")

    findings = scan_unified_diff(patch_text)

    if json_output:
        json_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(json.dumps([f.model_dump() for f in findings], indent=2), encoding="utf-8")

    if markdown_output:
        markdown_output.parent.mkdir(parents=True, exist_ok=True)
        markdown_output.write_text(generate_markdown_report(findings), encoding="utf-8")

    for finding in findings:
        click.echo(f"{finding.file_path}:{finding.line_number}: {finding.detector} -> {finding.secret_snippet}")

    if findings:
        raise SystemExit(1)
