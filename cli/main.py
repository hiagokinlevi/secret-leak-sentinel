from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click

from policies.loader import PolicyLoadError, load_policy
from scanners.engine import run_scan_path, run_scan_staged, run_scan_git


def _resolve_policy(policy_path: Optional[str], strict_policy: bool):
    """Load policy with optional strict error behavior.

    When strict_policy is False, policy load failures are downgraded to warning
    and scanner falls back to default policy behavior.
    When strict_policy is True, any policy load issue exits non-zero.
    """
    if not policy_path:
        return None

    try:
        return load_policy(policy_path)
    except (PolicyLoadError, FileNotFoundError, ValueError) as exc:
        if strict_policy:
            raise click.ClickException(
                f"Strict policy mode enabled: failed to load policy '{policy_path}': {exc}"
            )
        click.echo(
            f"[warn] Could not load policy '{policy_path}' ({exc}). Falling back to default policy.",
            err=True,
        )
        return None


@click.group()
def cli():
    pass


@cli.command("scan-path")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--policy", "policy_path", type=click.Path(path_type=Path), default=None, help="Path to YAML policy file.")
@click.option("--strict-policy", is_flag=True, default=False, help="Fail if --policy is missing, invalid, or fails schema validation.")
@click.option("--json-output", type=click.Path(path_type=Path), default=None)
def scan_path(path: Path, policy_path: Optional[Path], strict_policy: bool, json_output: Optional[Path]):
    policy = _resolve_policy(str(policy_path) if policy_path else None, strict_policy)
    result = run_scan_path(path=path, policy=policy)
    if json_output:
        json_output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    click.echo(json.dumps(result, indent=2))


@cli.command("scan-staged")
@click.option("--policy", "policy_path", type=click.Path(path_type=Path), default=None, help="Path to YAML policy file.")
@click.option("--strict-policy", is_flag=True, default=False, help="Fail if --policy is missing, invalid, or fails schema validation.")
@click.option("--json-output", type=click.Path(path_type=Path), default=None)
def scan_staged(policy_path: Optional[Path], strict_policy: bool, json_output: Optional[Path]):
    policy = _resolve_policy(str(policy_path) if policy_path else None, strict_policy)
    result = run_scan_staged(policy=policy)
    if json_output:
        json_output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    click.echo(json.dumps(result, indent=2))


@cli.command("scan-git")
@click.option("--policy", "policy_path", type=click.Path(path_type=Path), default=None, help="Path to YAML policy file.")
@click.option("--strict-policy", is_flag=True, default=False, help="Fail if --policy is missing, invalid, or fails schema validation.")
@click.option("--json-output", type=click.Path(path_type=Path), default=None)
def scan_git(policy_path: Optional[Path], strict_policy: bool, json_output: Optional[Path]):
    policy = _resolve_policy(str(policy_path) if policy_path else None, strict_policy)
    result = run_scan_git(policy=policy)
    if json_output:
        json_output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    click.echo(json.dumps(result, indent=2))
