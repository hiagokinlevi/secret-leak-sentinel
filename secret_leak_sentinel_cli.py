from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click

from cli.entrypoint import cli
from cli.policy import load_policy


# NOTE:
# This file wires CLI command options into policy loading behavior.
# Added --strict-policy support for scan commands so CI can fail deterministically
# when an explicit policy path is missing/unreadable/invalid.


def _policy_options(func):
    func = click.option(
        "--policy",
        type=click.Path(path_type=Path),
        required=False,
        help="Path to policy YAML file.",
    )(func)
    func = click.option(
        "--strict-policy",
        is_flag=True,
        default=False,
        help=(
            "Fail if --policy is missing, unreadable, or invalid instead of "
            "falling back to default policy."
        ),
    )(func)
    return func


def _load_policy_for_scan(policy: Optional[Path], strict_policy: bool):
    try:
        return load_policy(policy, strict=strict_policy)
    except Exception as exc:  # pragma: no cover - mapped to deterministic CLI error
        message = str(exc).strip() or "Policy loading failed"
        raise click.ClickException(f"Policy error: {message}")


@cli.command("scan-path")
@_policy_options
@click.argument("target", type=click.Path(path_type=Path))
def scan_path(target: Path, policy: Optional[Path], strict_policy: bool):
    _ = _load_policy_for_scan(policy, strict_policy)
    click.echo(json.dumps({"status": "ok", "command": "scan-path", "target": str(target)}))


@cli.command("scan-staged")
@_policy_options
def scan_staged(policy: Optional[Path], strict_policy: bool):
    _ = _load_policy_for_scan(policy, strict_policy)
    click.echo(json.dumps({"status": "ok", "command": "scan-staged"}))


@cli.command("scan-git")
@_policy_options
def scan_git(policy: Optional[Path], strict_policy: bool):
    _ = _load_policy_for_scan(policy, strict_policy)
    click.echo(json.dumps({"status": "ok", "command": "scan-git"}))


if __name__ == "__main__":
    cli()
