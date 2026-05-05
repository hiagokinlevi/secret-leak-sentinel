import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import click

from scanners.filesystem_scanner import FilesystemScanner
from scanners.git_scanner import GitScanner


def _fmt_bytes(num: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{num} B"


def _scan_files_with_limit(
    scanner: FilesystemScanner,
    file_paths: List[Path],
    max_file_bytes: Optional[int],
) -> Tuple[List[Dict[str, Any]], int, Dict[str, int]]:
    findings: List[Dict[str, Any]] = []
    skipped = 0
    skipped_reasons = {"max_file_bytes": 0}

    for path in file_paths:
        if max_file_bytes is not None:
            try:
                size = path.stat().st_size
            except OSError:
                size = None
            if size is not None and size > max_file_bytes:
                skipped += 1
                skipped_reasons["max_file_bytes"] += 1
                continue

        findings.extend(scanner.scan_file(path))

    return findings, skipped, skipped_reasons


def _scan_git_with_limit(
    scanner: GitScanner,
    repo_path: str,
    max_file_bytes: Optional[int],
) -> Tuple[List[Dict[str, Any]], int, Dict[str, int]]:
    findings: List[Dict[str, Any]] = []
    skipped = 0
    skipped_reasons = {"max_file_bytes": 0}

    for file_obj in scanner.iter_repository_files(repo_path):
        if max_file_bytes is not None:
            size = file_obj.get("size")
            if isinstance(size, int) and size > max_file_bytes:
                skipped += 1
                skipped_reasons["max_file_bytes"] += 1
                continue

        findings.extend(scanner.scan_repository_file(file_obj))

    return findings, skipped, skipped_reasons


@click.group()
def cli() -> None:
    pass


@cli.command("scan-path")
@click.argument("path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option("--json-output", type=click.Path(), default=None, help="Write findings JSON to file.")
@click.option(
    "--max-file-bytes",
    type=click.IntRange(min=1),
    default=None,
    help="Skip files larger than this byte threshold (default: no limit).",
)
def scan_path(path: str, json_output: Optional[str], max_file_bytes: Optional[int]) -> None:
    scanner = FilesystemScanner()
    file_paths = scanner.collect_files(path)
    findings, skipped_count, skipped_reasons = _scan_files_with_limit(scanner, file_paths, max_file_bytes)

    if json_output:
        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)

    click.echo(f"Scanned files: {len(file_paths) - skipped_count}/{len(file_paths)}")
    if max_file_bytes is not None:
        click.echo(
            f"Skipped files: {skipped_count} (reason: exceeds --max-file-bytes={max_file_bytes} / {_fmt_bytes(max_file_bytes)})"
        )
    click.echo(f"Findings: {len(findings)}")


@cli.command("scan-git")
@click.argument("repo_path", type=click.Path(exists=True, file_okay=False, dir_okay=True), default=".")
@click.option("--json-output", type=click.Path(), default=None, help="Write findings JSON to file.")
@click.option(
    "--max-file-bytes",
    type=click.IntRange(min=1),
    default=None,
    help="Skip repository files larger than this byte threshold (default: no limit).",
)
def scan_git(repo_path: str, json_output: Optional[str], max_file_bytes: Optional[int]) -> None:
    scanner = GitScanner()
    findings, skipped_count, skipped_reasons = _scan_git_with_limit(scanner, repo_path, max_file_bytes)

    if json_output:
        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)

    total = len(findings) + skipped_count
    click.echo(f"Processed repo files: {total - skipped_count}/{total}")
    if max_file_bytes is not None:
        click.echo(
            f"Skipped files: {skipped_count} (reason: exceeds --max-file-bytes={max_file_bytes} / {_fmt_bytes(max_file_bytes)})"
        )
    click.echo(f"Findings: {len(findings)}")


if __name__ == "__main__":
    cli()
