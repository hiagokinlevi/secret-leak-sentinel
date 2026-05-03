from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click

from scanners.filesystem_scanner import FilesystemScanner


@click.group()
def cli() -> None:
    """secret-leak-sentinel CLI."""


@cli.command("scan-path")
@click.argument("target_path", required=False, type=click.Path(path_type=Path))
@click.option("--json-output", "json_output", type=click.Path(path_type=Path), default=None)
@click.option("--from-stdin", "from_stdin", is_flag=True, default=False, help="Read raw content from stdin and scan as a virtual file.")
@click.option("--stdin-filename", "stdin_filename", default="<stdin>", show_default=True, help="Virtual filename used when scanning stdin content.")
def scan_path(
    target_path: Optional[Path],
    json_output: Optional[Path],
    from_stdin: bool,
    stdin_filename: str,
) -> None:
    """Scan a filesystem path (or stdin content) for secrets."""
    scanner = FilesystemScanner()

    if from_stdin:
        raw = sys.stdin.read()
        findings = scanner.scan_text(raw, source_name=stdin_filename)
    else:
        if target_path is None:
            raise click.UsageError("TARGET_PATH is required unless --from-stdin is provided")
        findings = scanner.scan_path(target_path)

    payload = {
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total_findings": len(findings),
        },
    }

    if json_output:
        json_output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    else:
        click.echo(json.dumps(payload, indent=2))

    raise SystemExit(1 if findings else 0)


if __name__ == "__main__":
    cli()
