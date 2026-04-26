import json
from pathlib import Path

import click

from scanners.filesystem_scanner import scan_path
from scanners.git_scanner import scan_git


@click.group()
def cli():
    """secret-leak-sentinel CLI."""


@cli.command("scan-path")
@click.argument("target_path", type=click.Path(path_type=Path, exists=True))
@click.option("--exclude", "excludes", multiple=True, help="Additional paths/patterns to exclude.")
@click.option("--no-default-excludes", is_flag=True, default=False, help="Disable built-in default exclusion paths.")
@click.option("--json-output", type=click.Path(path_type=Path), default=None, help="Write findings JSON to file.")
def scan_path_cmd(target_path: Path, excludes: tuple[str, ...], no_default_excludes: bool, json_output: Path | None):
    findings = scan_path(
        target_path,
        excludes=list(excludes),
        use_default_excludes=not no_default_excludes,
    )

    if json_output:
        json_output.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        click.echo(f"Wrote findings to {json_output}")
    else:
        click.echo(json.dumps(findings, indent=2))


@cli.command("scan-git")
@click.option("--repo", "repo_path", type=click.Path(path_type=Path, exists=True), default=Path("."), show_default=True)
@click.option("--include-history", is_flag=True, default=False, help="Scan full git history.")
@click.option("--exclude", "excludes", multiple=True, help="Additional paths/patterns to exclude.")
@click.option("--no-default-excludes", is_flag=True, default=False, help="Disable built-in default exclusion paths.")
@click.option("--json-output", type=click.Path(path_type=Path), default=None, help="Write findings JSON to file.")
def scan_git_cmd(repo_path: Path, include_history: bool, excludes: tuple[str, ...], no_default_excludes: bool, json_output: Path | None):
    findings = scan_git(
        repo_path,
        include_history=include_history,
        excludes=list(excludes),
        use_default_excludes=not no_default_excludes,
    )

    if json_output:
        json_output.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        click.echo(f"Wrote findings to {json_output}")
    else:
        click.echo(json.dumps(findings, indent=2))


if __name__ == "__main__":
    cli()
