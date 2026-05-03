from __future__ import annotations

import json
from pathlib import Path

import click

from reports.generator import generate_report


@click.command("generate-report")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False))
@click.option(
    "--output-format",
    type=click.Choice(["markdown", "json", "sarif"], case_sensitive=False),
    default="markdown",
    show_default=True,
)
def generate_report_command(input_path: str, output_path: str, output_format: str) -> None:
    with open(input_path, "r", encoding="utf-8") as f:
        findings = json.load(f)

    rendered = generate_report(findings=findings, output_format=output_format)

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(rendered, encoding="utf-8")

    click.echo(f"Report written to {output_file} ({output_format.lower()})")
