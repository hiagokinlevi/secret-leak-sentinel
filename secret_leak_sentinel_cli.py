import json
from pathlib import Path

import click

from scanners.filesystem_scanner import scan_path as scan_filesystem_path


@click.group()
def cli():
    """secret-leak-sentinel CLI."""
    pass


@cli.command("scan-path")
@click.argument("target_path", type=click.Path(exists=True, path_type=Path))
@click.option("--policy", "policy_path", type=click.Path(exists=True, path_type=Path), default=None, help="Optional policy file path.")
@click.option("--exclude", "exclude_patterns", multiple=True, help="Repeatable glob/path exclude pattern.")
@click.option(
    "--allowed-extension",
    "allowed_extensions",
    multiple=True,
    help="Repeatable file extension include filter (e.g. --allowed-extension .py --allowed-extension .yaml). Applied after excludes.",
)
@click.option("--json-output", "json_output", is_flag=True, default=False, help="Emit JSON findings.")
def scan_path_command(target_path: Path, policy_path: Path | None, exclude_patterns: tuple[str, ...], allowed_extensions: tuple[str, ...], json_output: bool):
    """Scan a filesystem path for potential secrets."""
    normalized_extensions = None
    if allowed_extensions:
        normalized_extensions = tuple(
            ext if ext.startswith(".") else f".{ext}"
            for ext in allowed_extensions
        )

    findings = scan_filesystem_path(
        target_path=target_path,
        policy_path=policy_path,
        exclude_patterns=list(exclude_patterns),
        allowed_extensions=list(normalized_extensions) if normalized_extensions else None,
    )

    if json_output:
        click.echo(json.dumps(findings, indent=2))
    else:
        click.echo(f"Findings: {len(findings)}")


if __name__ == "__main__":
    cli()
