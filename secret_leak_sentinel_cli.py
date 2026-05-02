import json
import os
from pathlib import Path

import click

from scanners.git_scanner import GitScanner
from scanners.path_scanner import PathScanner
from reports.markdown_report import MarkdownReportGenerator


@click.group()
def cli() -> None:
    """secret-leak-sentinel CLI."""
    pass


@cli.command("scan-git")
@click.option("--repo", "repo_path", default=".", show_default=True, help="Path to git repository")
@click.option("--deep-history", is_flag=True, help="Scan full git history (all commits)")
@click.option(
    "--history-max-commits",
    type=click.IntRange(min=1),
    default=None,
    help="When used with --deep-history, only scan the most recent N commits",
)
@click.option("--json-output", type=click.Path(), default=None, help="Write findings to JSON file")
@click.option("--markdown-output", type=click.Path(), default=None, help="Write findings to Markdown report")
def scan_git(
    repo_path: str,
    deep_history: bool,
    history_max_commits: int | None,
    json_output: str | None,
    markdown_output: str | None,
) -> None:
    scanner = GitScanner(repo_path)

    if deep_history:
        findings = scanner.scan_history(max_commits=history_max_commits)
    else:
        findings = scanner.scan_working_tree()

    if json_output:
        out = Path(json_output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    if markdown_output:
        out = Path(markdown_output)
        out.parent.mkdir(parents=True, exist_ok=True)
        report = MarkdownReportGenerator().generate(findings)
        out.write_text(report, encoding="utf-8")

    click.echo(json.dumps({"findings": len(findings)}))


@cli.command("scan-path")
@click.option("--path", "target_path", default=".", show_default=True, help="Path to scan")
def scan_path(target_path: str) -> None:
    scanner = PathScanner(target_path)
    findings = scanner.scan()
    click.echo(json.dumps({"findings": len(findings)}))


if __name__ == "__main__":
    cli()
