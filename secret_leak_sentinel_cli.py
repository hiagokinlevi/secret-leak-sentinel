import json
from pathlib import Path

import click

from cli.commands import (
    handle_generate_report,
    handle_list_detectors,
    handle_scan_file,
    handle_scan_git,
    handle_scan_path,
    handle_scan_staged,
    handle_validate_policy,
)


def _load_baseline_fingerprints(baseline_path: str | None) -> set[str]:
    if not baseline_path:
        return set()

    baseline_file = Path(baseline_path)
    if not baseline_file.exists():
        raise click.ClickException(f"Baseline file not found: {baseline_path}")

    try:
        payload = json.loads(baseline_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise click.ClickException(f"Failed to parse baseline JSON: {baseline_path} ({exc})")

    findings = payload.get("findings", []) if isinstance(payload, dict) else []
    fingerprints: set[str] = set()
    for finding in findings:
        if isinstance(finding, dict):
            fp = finding.get("fingerprint")
            if isinstance(fp, str) and fp:
                fingerprints.add(fp)
    return fingerprints


def _apply_baseline_filter(result: dict, baseline_fingerprints: set[str]) -> dict:
    if not baseline_fingerprints:
        return result

    findings = result.get("findings", []) if isinstance(result, dict) else []
    if not isinstance(findings, list):
        return result

    filtered = []
    for finding in findings:
        if not isinstance(finding, dict):
            filtered.append(finding)
            continue
        fp = finding.get("fingerprint")
        if not (isinstance(fp, str) and fp in baseline_fingerprints):
            filtered.append(finding)

    result["findings"] = filtered
    result["summary"] = {
        **(result.get("summary", {}) if isinstance(result.get("summary"), dict) else {}),
        "total_findings": len(filtered),
    }
    return result


@click.group()
def cli():
    """secret-leak-sentinel CLI"""


@cli.command("scan-path")
@click.option("--path", "path_", required=True, type=click.Path(exists=True))
@click.option("--policy", default=None, type=click.Path(exists=True))
@click.option("--format", "output_format", default="text", type=click.Choice(["text", "json"]))
@click.option("--output", default=None, type=click.Path())
@click.option("--baseline", default=None, type=click.Path(exists=True))
def scan_path(path_, policy, output_format, output, baseline):
    """Scan a filesystem path for leaked secrets."""
    handle_scan_path(path_, policy, output_format, output, baseline)


@cli.command("scan-file")
@click.option("--file", "file_path", required=True, type=click.Path(exists=True))
@click.option("--policy", default=None, type=click.Path(exists=True))
@click.option("--json-output", "json_output", default=None, type=click.Path())
def scan_file(file_path, policy, json_output):
    """Scan a single file for leaked secrets."""
    handle_scan_file(file_path, policy, json_output)


@cli.command("scan-staged")
@click.option("--policy", default=None, type=click.Path(exists=True))
@click.option("--format", "output_format", default="text", type=click.Choice(["text", "json"]))
@click.option("--output", default=None, type=click.Path())
@click.option("--baseline", default=None, type=click.Path())
def scan_staged(policy, output_format, output, baseline):
    """Scan currently staged git changes for leaked secrets."""
    baseline_fingerprints = _load_baseline_fingerprints(baseline)
    result = handle_scan_staged(policy, output_format="json", output=None)
    result = _apply_baseline_filter(result, baseline_fingerprints)

    if output_format == "json":
        rendered = json.dumps(result, indent=2)
        if output:
            Path(output).write_text(rendered, encoding="utf-8")
        else:
            click.echo(rendered)
    else:
        findings = result.get("findings", [])
        if findings:
            click.echo(f"Found {len(findings)} potential secret(s) in staged changes.")
        else:
            click.echo("No secrets found in staged changes.")


@cli.command("scan-git")
@click.option("--repo", "repo_path", default=".", type=click.Path(exists=True))
@click.option("--history", is_flag=True, default=False)
@click.option("--max-commits", default=None, type=int)
@click.option("--policy", default=None, type=click.Path(exists=True))
@click.option("--format", "output_format", default="text", type=click.Choice(["text", "json"]))
@click.option("--output", default=None, type=click.Path())
@click.option("--baseline", default=None, type=click.Path())
def scan_git(repo_path, history, max_commits, policy, output_format, output, baseline):
    """Scan git repository working tree or history for leaked secrets."""
    baseline_fingerprints = _load_baseline_fingerprints(baseline)
    result = handle_scan_git(
        repo_path=repo_path,
        history=history,
        max_commits=max_commits,
        policy=policy,
        output_format="json",
        output=None,
    )
    result = _apply_baseline_filter(result, baseline_fingerprints)

    if output_format == "json":
        rendered = json.dumps(result, indent=2)
        if output:
            Path(output).write_text(rendered, encoding="utf-8")
        else:
            click.echo(rendered)
    else:
        findings = result.get("findings", [])
        mode = "history" if history else "working tree"
        if findings:
            click.echo(f"Found {len(findings)} potential secret(s) in git {mode} scan.")
        else:
            click.echo(f"No secrets found in git {mode} scan.")


@cli.command("validate-policy")
@click.option("--policy", "policy_path", required=True, type=click.Path(exists=True))
def validate_policy(policy_path):
    """Validate a policy file."""
    handle_validate_policy(policy_path)


@cli.command("generate-report")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True))
@click.option("--output", "output_path", required=True, type=click.Path())
def generate_report(input_path, output_path):
    """Generate markdown report from JSON results."""
    handle_generate_report(input_path, output_path)


@cli.command("list-detectors")
def list_detectors():
    """List available detectors."""
    handle_list_detectors()


if __name__ == "__main__":
    cli()
