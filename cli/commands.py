from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from scanners.git_scanner import scan_git_history, scan_staged_changes


def _emit_and_optionally_write(results: dict[str, Any], json_output: bool, output_file: str | None) -> None:
    rendered = json.dumps(results, indent=2) if json_output else str(results)
    click.echo(rendered)
    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")


@click.group()
def cli() -> None:
    pass


@cli.command("scan-staged")
@click.option("--json-output", is_flag=True, default=False, help="Emit JSON output")
@click.option("--output-file", type=click.Path(dir_okay=False, path_type=str), default=None, help="Optional file path to also write report output")
def scan_staged_cmd(json_output: bool, output_file: str | None) -> None:
    results = scan_staged_changes()
    _emit_and_optionally_write(results, json_output=json_output, output_file=output_file)


@cli.command("scan-git")
@click.option("--json-output", is_flag=True, default=False, help="Emit JSON output")
@click.option("--output-file", type=click.Path(dir_okay=False, path_type=str), default=None, help="Optional file path to also write report output")
def scan_git_cmd(json_output: bool, output_file: str | None) -> None:
    results = scan_git_history()
    _emit_and_optionally_write(results, json_output=json_output, output_file=output_file)
