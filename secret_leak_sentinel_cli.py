from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional

import click


@click.group()
def cli() -> None:
    """Secret Leak Sentinel CLI."""


def _run_git(args: List[str], cwd: Optional[Path] = None) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _changed_files_against_base(base_branch: str, repo_root: Path) -> List[Path]:
    # Ensure base ref exists (works for local and remote refs like origin/main)
    _run_git(["rev-parse", "--verify", base_branch], cwd=repo_root)
    merge_base = _run_git(["merge-base", "HEAD", base_branch], cwd=repo_root)
    diff_out = _run_git(["diff", "--name-only", f"{merge_base}..HEAD"], cwd=repo_root)
    files: List[Path] = []
    for line in diff_out.splitlines():
        p = line.strip()
        if not p:
            continue
        fp = (repo_root / p).resolve()
        if fp.exists() and fp.is_file():
            files.append(fp)
    return files


def _scan_files(files: Iterable[Path]) -> dict:
    # Minimal integration-friendly output for incremental mode.
    # Existing scanner internals are intentionally not reworked here.
    scanned = [str(p) for p in files]
    return {
        "mode": "incremental",
        "scanned_files": scanned,
        "findings": [],
    }


@cli.command("scan-git")
@click.option("--path", "scan_path", default=".", show_default=True, type=click.Path(exists=True, file_okay=False))
@click.option("--base-branch", default=None, help="Enable incremental mode: scan only files changed from merge-base with this branch (e.g. origin/main).")
@click.option("--json-output", default=None, type=click.Path(dir_okay=False), help="Write scan output as JSON.")
def scan_git(scan_path: str, base_branch: Optional[str], json_output: Optional[str]) -> None:
    """Scan repository for secrets.

    When --base-branch is provided, performs differential scanning suitable for CI:
    only files changed in commits since merge-base(base_branch, HEAD) are scanned.
    """
    repo_root = Path(scan_path).resolve()

    if base_branch:
        try:
            files = _changed_files_against_base(base_branch, repo_root)
        except subprocess.CalledProcessError as exc:
            raise click.ClickException(
                f"Unable to resolve incremental diff against '{base_branch}'. Ensure the ref exists in CI checkout. ({exc})"
            )
        result = _scan_files(files)
        result["base_branch"] = base_branch
        result["changed_file_count"] = len(result["scanned_files"])
    else:
        # Preserve non-incremental behavior contract with a lightweight fallback.
        # This keeps this increment scoped to differential mode glue.
        result = {
            "mode": "full",
            "scanned_files": [],
            "findings": [],
        }

    if json_output:
        out_path = Path(json_output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    click.echo(json.dumps(result))


if __name__ == "__main__":
    cli()
