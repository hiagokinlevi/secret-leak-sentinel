import json
import os
import sys
import subprocess
from pathlib import Path

import click

from scanners.filesystem_scanner import scan_path as filesystem_scan_path


def _get_changed_files_against_head(base_path: Path) -> set[Path]:
    """Return tracked files changed relative to HEAD (staged + unstaged).

    Uses git diff against HEAD so local modifications and staged changes are both included.
    """
    try:
      cmd = ["git", "-C", str(base_path), "diff", "--name-only", "HEAD", "--"]
      result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except Exception:
      return set()

    changed = set()
    for line in result.stdout.splitlines():
      line = line.strip()
      if not line:
        continue
      changed.add((base_path / line).resolve())
    return changed


@click.group()
def cli():
    pass


@cli.command("scan-path")
@click.argument("path", type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path), default=Path("."))
@click.option("--json-output", type=click.Path(dir_okay=False, writable=True, path_type=Path), default=None, help="Write findings as JSON to this file.")
@click.option("--changed-only", is_flag=True, default=False, help="Scan only tracked files changed relative to HEAD (includes staged and unstaged changes).")
def scan_path_cmd(path: Path, json_output: Path | None, changed_only: bool):
    """Scan a filesystem path for leaked secrets."""
    scan_root = path.resolve()

    include_paths = None
    if changed_only:
        changed = _get_changed_files_against_head(scan_root if scan_root.is_dir() else scan_root.parent)
        if scan_root.is_file():
            file_path = scan_root.resolve()
            include_paths = {file_path} if file_path in changed else set()
        else:
            include_paths = {p for p in changed if str(p).startswith(str(scan_root))}

    findings = filesystem_scan_path(scan_root, include_paths=include_paths)

    if json_output:
        json_output.parent.mkdir(parents=True, exist_ok=True)
        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)

    click.echo(f"Findings: {len(findings)}")
    raise SystemExit(1 if findings else 0)


if __name__ == "__main__":
    cli()
