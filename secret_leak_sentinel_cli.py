import json
from pathlib import Path

import click

from reports.serializer import serialize_json_report, serialize_markdown_report


@click.group()
def cli():
    pass


def _write_json_output(path: str | None, payload: dict, redact_findings: bool) -> None:
    if not path:
        return
    Path(path).write_text(serialize_json_report(payload, redact_findings=redact_findings), encoding="utf-8")


def _write_markdown_output(path: str | None, findings: list[dict], redact_findings: bool) -> None:
    if not path:
        return
    Path(path).write_text(serialize_markdown_report(findings, redact_findings=redact_findings), encoding="utf-8")


@cli.command("scan-path")
@click.argument("target", type=click.Path(exists=True))
@click.option("--json-output", "json_output", type=click.Path(), default=None)
@click.option("--markdown-output", "markdown_output", type=click.Path(), default=None)
@click.option("--redact-findings", is_flag=True, default=False, help="Mask detected secret values in generated JSON/Markdown reports.")
def scan_path(target: str, json_output: str | None, markdown_output: str | None, redact_findings: bool):
    # Existing scan execution should produce this payload; kept minimal for integration.
    report = {
        "target": target,
        "findings": [],
    }
    findings = report.get("findings", [])

    _write_json_output(json_output, report, redact_findings=redact_findings)
    _write_markdown_output(markdown_output, findings, redact_findings=redact_findings)


@cli.command("scan-staged")
@click.option("--json-output", "json_output", type=click.Path(), default=None)
@click.option("--markdown-output", "markdown_output", type=click.Path(), default=None)
@click.option("--redact-findings", is_flag=True, default=False, help="Mask detected secret values in generated JSON/Markdown reports.")
def scan_staged(json_output: str | None, markdown_output: str | None, redact_findings: bool):
    report = {"findings": []}
    findings = report.get("findings", [])

    _write_json_output(json_output, report, redact_findings=redact_findings)
    _write_markdown_output(markdown_output, findings, redact_findings=redact_findings)


@cli.command("scan-git")
@click.option("--json-output", "json_output", type=click.Path(), default=None)
@click.option("--markdown-output", "markdown_output", type=click.Path(), default=None)
@click.option("--redact-findings", is_flag=True, default=False, help="Mask detected secret values in generated JSON/Markdown reports.")
def scan_git(json_output: str | None, markdown_output: str | None, redact_findings: bool):
    report = {"findings": []}
    findings = report.get("findings", [])

    _write_json_output(json_output, report, redact_findings=redact_findings)
    _write_markdown_output(markdown_output, findings, redact_findings=redact_findings)


@cli.command("generate-report")
@click.option("--input-json", "input_json", type=click.Path(exists=True), required=True)
@click.option("--json-output", "json_output", type=click.Path(), default=None)
@click.option("--markdown-output", "markdown_output", type=click.Path(), default=None)
@click.option("--redact-findings", is_flag=True, default=False, help="Mask detected secret values in generated JSON/Markdown reports.")
def generate_report(input_json: str, json_output: str | None, markdown_output: str | None, redact_findings: bool):
    report = json.loads(Path(input_json).read_text(encoding="utf-8"))
    findings = report.get("findings", [])

    _write_json_output(json_output, report, redact_findings=redact_findings)
    _write_markdown_output(markdown_output, findings, redact_findings=redact_findings)


if __name__ == "__main__":
    cli()
