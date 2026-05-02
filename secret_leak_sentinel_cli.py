import json
import os
from pathlib import Path

import click

from classifiers.criticality import classify_findings
from detectors.engine import scan_content
from reports.markdown import generate_markdown_report
from scanners.filesystem import scan_path as scanner_scan_path
from scanners.git_scanner import scan_git_history, scan_staged_changes, scan_working_tree


def _emit_output(findings, json_output=None, markdown_output=None, title="Secret Leak Sentinel Report"):
    if json_output:
        Path(json_output).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    else:
        click.echo(json.dumps(findings, indent=2))

    if markdown_output:
        Path(markdown_output).write_text(generate_markdown_report(findings, title=title), encoding="utf-8")


def _should_fail_by_severity(findings, fail_on_severity):
    if not fail_on_severity:
        return False
    threshold = fail_on_severity.lower()
    ordered = ["low", "medium", "high", "critical"]
    if threshold not in ordered:
        raise click.BadParameter(f"Invalid --fail-on-severity value: {fail_on_severity}")
    min_index = ordered.index(threshold)
    for f in findings:
        sev = str(f.get("severity", "low")).lower()
        if sev in ordered and ordered.index(sev) >= min_index:
            return True
    return False


def _determine_exit_code(findings, fail_on_severity=None, exit_code_on_findings=False):
    if exit_code_on_findings and findings:
        return 1
    if _should_fail_by_severity(findings, fail_on_severity):
        return 1
    return 0


@click.group()
def cli():
    """secret-leak-sentinel CLI"""


@cli.command("scan-path")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--json-output", type=click.Path(path_type=Path), help="Write JSON findings to file")
@click.option("--markdown-output", type=click.Path(path_type=Path), help="Write Markdown report to file")
@click.option("--fail-on-severity", type=str, default=None, help="Exit non-zero if findings meet/exceed severity (low|medium|high|critical)")
@click.option("--exit-code-on-findings", is_flag=True, default=False, help="Exit with code 1 if any findings are produced")
def scan_path_cmd(path, json_output, markdown_output, fail_on_severity, exit_code_on_findings):
    findings = scanner_scan_path(str(path))
    findings = classify_findings(findings)
    _emit_output(findings, json_output=json_output, markdown_output=markdown_output, title=f"Scan Path: {path}")
    raise SystemExit(_determine_exit_code(findings, fail_on_severity, exit_code_on_findings))


@cli.command("scan-staged")
@click.option("--repo", "repo_path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=Path("."), show_default=True, help="Path to git repository")
@click.option("--json-output", type=click.Path(path_type=Path), help="Write JSON findings to file")
@click.option("--markdown-output", type=click.Path(path_type=Path), help="Write Markdown report to file")
@click.option("--fail-on-severity", type=str, default=None, help="Exit non-zero if findings meet/exceed severity (low|medium|high|critical)")
@click.option("--exit-code-on-findings", is_flag=True, default=False, help="Exit with code 1 if any findings are produced")
def scan_staged_cmd(repo_path, json_output, markdown_output, fail_on_severity, exit_code_on_findings):
    findings = scan_staged_changes(str(repo_path))
    findings = classify_findings(findings)
    _emit_output(findings, json_output=json_output, markdown_output=markdown_output, title=f"Scan Staged: {repo_path}")
    raise SystemExit(_determine_exit_code(findings, fail_on_severity, exit_code_on_findings))


@cli.command("scan-git")
@click.option("--repo", "repo_path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=Path("."), show_default=True, help="Path to git repository")
@click.option("--history", is_flag=True, default=False, help="Scan full git history instead of working tree")
@click.option("--json-output", type=click.Path(path_type=Path), help="Write JSON findings to file")
@click.option("--markdown-output", type=click.Path(path_type=Path), help="Write Markdown report to file")
@click.option("--fail-on-severity", type=str, default=None, help="Exit non-zero if findings meet/exceed severity (low|medium|high|critical)")
@click.option("--exit-code-on-findings", is_flag=True, default=False, help="Exit with code 1 if any findings are produced")
def scan_git_cmd(repo_path, history, json_output, markdown_output, fail_on_severity, exit_code_on_findings):
    if history:
        findings = scan_git_history(str(repo_path))
        title = f"Scan Git History: {repo_path}"
    else:
        findings = scan_working_tree(str(repo_path))
        title = f"Scan Git Working Tree: {repo_path}"

    findings = classify_findings(findings)
    _emit_output(findings, json_output=json_output, markdown_output=markdown_output, title=title)
    raise SystemExit(_determine_exit_code(findings, fail_on_severity, exit_code_on_findings))


@cli.command("scan-file")
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def scan_file_cmd(file):
    content = file.read_text(encoding="utf-8", errors="ignore")
    findings = classify_findings(scan_content(content, source=str(file)))
    click.echo(json.dumps(findings, indent=2))


@cli.command("generate-report")
@click.argument("input_json", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("output_md", type=click.Path(path_type=Path))
@click.option("--title", default="Secret Leak Sentinel Report", show_default=True)
def generate_report_cmd(input_json, output_md, title):
    findings = json.loads(input_json.read_text(encoding="utf-8"))
    output_md.write_text(generate_markdown_report(findings, title=title), encoding="utf-8")
    click.echo(f"Wrote report to {output_md}")


if __name__ == "__main__":
    cli()
