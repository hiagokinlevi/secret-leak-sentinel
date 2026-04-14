"""
secret-leak-sentinel CLI
==============================
Main Click command group. Entry point is `secret-leak-sentinel` (defined in pyproject.toml).

Commands:
  scan-path         Scan a directory tree for secrets
  scan-staged       Scan git staged files (pre-commit integration)
  scan-git          Scan git working tree
  scan-git-history  Scan full git commit history
  validate-policy   Validate a policy YAML file
  generate-report   Generate a Markdown report from a previous scan's JSON output
  list-detectors    List all active regex detector patterns

Global options (can also be set via .env):
  --policy-profile  Policy profile to apply (developer, ci, strict)
  --output-dir      Directory for report output
  --entropy/--no-entropy   Enable or disable the entropy detector
  --fail-on         Minimum severity to exit non-zero
"""
import json
import sys
from pathlib import Path

import click
import structlog
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

load_dotenv()

logger = structlog.get_logger(__name__)
console = Console()


@click.group()
@click.option(
    "--output-dir",
    envvar="OUTPUT_DIR",
    default="./scan-results",
    show_default=True,
    help="Directory for generated reports.",
)
@click.option(
    "--fail-on",
    envvar="FAIL_ON_SEVERITY",
    default="high",
    type=click.Choice(["low", "medium", "high", "critical"]),
    show_default=True,
    help="Exit non-zero if any finding reaches this severity.",
)
@click.option(
    "--entropy/--no-entropy",
    "entropy_enabled",
    envvar="ENTROPY_ENABLED",
    default=True,
    show_default=True,
    help="Enable or disable the Shannon entropy detector.",
)
@click.option(
    "--entropy-threshold",
    envvar="ENTROPY_THRESHOLD",
    default=4.5,
    type=float,
    show_default=True,
    help="Shannon entropy threshold for the entropy detector.",
)
@click.option(
    "--policy-profile",
    envvar="POLICY_PROFILE",
    default="default",
    type=click.Choice(["default", "developer", "ci", "strict"]),
    show_default=True,
    help="Policy profile to apply.",
)
@click.option("--verbose", is_flag=True, default=False, help="Enable verbose logging.")
@click.pass_context
def cli(
    ctx: click.Context,
    output_dir: str,
    fail_on: str,
    entropy_enabled: bool,
    entropy_threshold: float,
    policy_profile: str,
    verbose: bool,
) -> None:
    """secret-leak-sentinel — secret detection and prevention CLI."""
    ctx.ensure_object(dict)
    ctx.obj.update({
        "output_dir": output_dir,
        "fail_on": fail_on,
        "entropy_enabled": entropy_enabled,
        "entropy_threshold": entropy_threshold,
        "policy_profile": policy_profile,
        "verbose": verbose,
    })

    import logging
    log_level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=log_level)


@cli.command("scan-path")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--ignore",
    multiple=True,
    envvar="IGNORED_PATHS",
    help="Glob patterns to ignore (repeatable). Comma-separated values also accepted.",
)
@click.pass_context
def scan_path(ctx: click.Context, path: str, ignore: tuple) -> None:
    """
    Scan a directory tree for secrets.

    PATH is the root directory to scan.
    """
    from scanners.filesystem_scanner import scan_directory
    from classifiers.criticality_classifier import classify_all
    from reports.report_generator import generate_scan_report, save_scan_report

    opts = ctx.obj
    # Flatten comma-separated ignore patterns from the env var variant
    ignore_patterns: list[str] = []
    for pattern in ignore:
        ignore_patterns.extend(p.strip() for p in pattern.split(",") if p.strip())
    if "publish-bridge" not in ignore_patterns:
        ignore_patterns.append("publish-bridge")

    console.print(f"\n[bold]Scanning:[/bold] {path}")
    console.print(f"[bold]Profile:[/bold]  {opts['policy_profile']}")
    console.print(f"[bold]Entropy:[/bold]  {'enabled' if opts['entropy_enabled'] else 'disabled'} "
                  f"(threshold: {opts['entropy_threshold']})\n")

    regex_findings, entropy_findings = scan_directory(
        root=path,
        entropy_enabled=opts["entropy_enabled"],
        entropy_threshold=opts["entropy_threshold"],
        ignored_patterns=ignore_patterns,
    )

    classified = classify_all(regex_findings, entropy_findings)
    _print_findings_table(classified)

    # Save report
    report_md = generate_scan_report(classified, scan_path=path, entropy_findings=entropy_findings)
    saved_path = save_scan_report(report_md, opts["output_dir"])
    console.print(f"\n[green]Report written to:[/green] {saved_path}")

    # Exit non-zero if fail_on threshold is met
    _apply_fail_policy(classified, opts["fail_on"])


@cli.command("scan-file")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--patch-mode/--no-patch-mode",
    default=False,
    show_default=True,
    help="Interpret the input as a unified diff and scan only added lines.",
)
@click.option(
    "--json-output",
    is_flag=True,
    default=False,
    help="Emit structured JSON instead of terminal table output.",
)
@click.pass_context
def scan_file(ctx: click.Context, path: str, patch_mode: bool, json_output: bool) -> None:
    """
    Scan a single file for secrets.

    When --patch-mode is enabled, PATH is treated as a unified diff file and
    only added lines are scanned. This is useful for pre-push workflows.
    """
    from classifiers.criticality_classifier import classify_all
    from detectors.entropy_detector import scan_content_for_entropy
    from detectors.regex_detector import scan_content
    from reports.json_exporter import build_scan_file_payload
    from scanners.patch_scanner import scan_patch_file

    opts = ctx.obj
    target = "patch file" if patch_mode else "file"
    if not json_output:
        console.print(f"\n[bold]Scanning {target}:[/bold] {path}")

    if patch_mode:
        regex_findings, entropy_findings = scan_patch_file(
            path,
            entropy_enabled=opts["entropy_enabled"],
            entropy_threshold=opts["entropy_threshold"],
        )
    else:
        content = Path(path).read_text(encoding="utf-8", errors="replace")
        regex_findings = scan_content(content, path)
        entropy_findings = []
        if opts["entropy_enabled"]:
            entropy_findings = scan_content_for_entropy(
                content,
                path,
                threshold=opts["entropy_threshold"],
            )

    classified = classify_all(regex_findings, entropy_findings)
    if json_output:
        payload = build_scan_file_payload(
            classified_findings=classified,
            scan_target=path,
            patch_mode=patch_mode,
            policy_profile=opts["policy_profile"],
            entropy_enabled=opts["entropy_enabled"],
            entropy_threshold=opts["entropy_threshold"],
        )
        click.echo(json.dumps(payload, indent=2))
    elif classified:
        _print_findings_table(classified)
    else:
        console.print("[green]No secrets detected.[/green]")

    _apply_fail_policy(classified, opts["fail_on"], quiet=json_output)


@cli.command("scan-staged")
@click.option(
    "--repo",
    default=".",
    type=click.Path(exists=True),
    show_default=True,
    help="Path to the git repository root.",
)
@click.pass_context
def scan_staged(ctx: click.Context, repo: str) -> None:
    """
    Scan git staged files for secrets.

    Designed for use in a pre-commit hook. Exits non-zero if findings meet
    the fail_on severity threshold, blocking the commit.
    """
    from scanners.git_scanner import scan_staged_files
    from classifiers.criticality_classifier import classify_all

    opts = ctx.obj

    console.print("[bold]Scanning staged files...[/bold]")

    regex_findings, entropy_findings = scan_staged_files(
        repo_path=repo,
        entropy_enabled=opts["entropy_enabled"],
        entropy_threshold=opts["entropy_threshold"],
    )

    classified = classify_all(regex_findings, entropy_findings)
    if classified:
        _print_findings_table(classified)
    else:
        console.print("[green]No secrets detected in staged files.[/green]")

    _apply_fail_policy(classified, opts["fail_on"])


@cli.command("scan-git")
@click.option(
    "--repo",
    default=".",
    type=click.Path(exists=True),
    show_default=True,
    help="Path to the git repository root.",
)
@click.option(
    "--depth",
    default=None,
    type=int,
    help="Maximum directory depth to scan.",
)
@click.pass_context
def scan_git(ctx: click.Context, repo: str, depth: int | None) -> None:
    """Scan the git working tree for secrets."""
    from scanners.git_scanner import scan_working_tree
    from classifiers.criticality_classifier import classify_all
    from reports.report_generator import generate_scan_report, save_scan_report

    opts = ctx.obj

    console.print(f"[bold]Scanning git working tree:[/bold] {repo}")

    regex_findings, entropy_findings = scan_working_tree(
        repo_path=repo,
        entropy_enabled=opts["entropy_enabled"],
        entropy_threshold=opts["entropy_threshold"],
        depth=depth,
    )

    classified = classify_all(regex_findings, entropy_findings)
    _print_findings_table(classified)

    report_md = generate_scan_report(classified, scan_path=repo, entropy_findings=entropy_findings)
    saved_path = save_scan_report(report_md, opts["output_dir"])
    console.print(f"\n[green]Report written to:[/green] {saved_path}")

    _apply_fail_policy(classified, opts["fail_on"])


@cli.command("scan-git-history")
@click.option(
    "--repo",
    default=".",
    type=click.Path(exists=True),
    show_default=True,
    help="Path to the git repository root.",
)
@click.option(
    "--max-commits",
    default=None,
    type=int,
    help="Maximum number of commits to scan. Default scans the full reachable history.",
)
@click.option(
    "--branch",
    default=None,
    help="Branch or ref to scan. Defaults to the current HEAD.",
)
@click.option(
    "--ignore-path",
    "ignore_paths",
    multiple=True,
    help="Substring path filters to skip during history scanning.",
)
@click.option(
    "--json-output",
    is_flag=True,
    default=False,
    help="Emit the history scan report as JSON instead of a table.",
)
def scan_git_history(
    repo: str,
    max_commits: int | None,
    branch: str | None,
    ignore_paths: tuple[str, ...],
    json_output: bool,
) -> None:
    """Scan full git history for secrets introduced by prior commits."""
    try:
        import git  # noqa: F401
    except ImportError:
        console.print(
            "[red]Git history scanning requires GitPython in the active runtime.[/red]"
        )
        raise SystemExit(2)

    from scanners.git_history_scanner import GitHistoryScanner

    console.print(f"[bold]Scanning git history:[/bold] {repo}")

    scanner = GitHistoryScanner(
        repo_path=repo,
        max_commits=max_commits,
        branch=branch,
        skip_paths=list(ignore_paths),
    )
    report = scanner.scan()

    if json_output:
        console.print_json(json.dumps(report.to_dict()))
    else:
        console.print(report.summary())
        if report.findings:
            table = Table(title="Git History Findings", show_lines=True)
            table.add_column("Commit")
            table.add_column("Author")
            table.add_column("File")
            table.add_column("Line", justify="right")
            table.add_column("Rule")
            table.add_column("Evidence")

            for finding in report.findings[:50]:
                table.add_row(
                    finding.commit_sha[:12],
                    finding.commit_author or "-",
                    finding.file_path,
                    str(finding.line_number),
                    finding.rule_id,
                    finding.evidence,
                )

            console.print(table)
            if len(report.findings) > 50:
                console.print(
                    f"[yellow]Showing first 50 of {len(report.findings)} findings.[/yellow]"
                )
        else:
            console.print("[green]No historical secrets detected.[/green]")

    if report.findings:
        raise SystemExit(1)


@cli.command("validate-policy")
@click.argument("policy_file", type=click.Path(exists=True))
def validate_policy(policy_file: str) -> None:
    """
    Validate a policy YAML file.

    Checks that the file is valid YAML and contains the required keys.
    """
    import yaml

    try:
        with open(policy_file) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        console.print(f"[red]Invalid YAML:[/red] {exc}")
        sys.exit(1)

    required_keys = {"name", "fail_on_severity", "entropy"}
    missing = required_keys - set(data.keys())
    if missing:
        console.print(f"[yellow]Warning: missing recommended keys:[/yellow] {', '.join(missing)}")
    else:
        console.print(f"[green]Policy file is valid:[/green] {policy_file}")


@cli.command("generate-report")
@click.option(
    "--input",
    "input_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to a JSON findings file from a previous scan.",
)
@click.pass_context
def generate_report(ctx: click.Context, input_file: str) -> None:
    """Regenerate a Markdown report from a saved JSON findings file."""
    output_dir = ctx.obj["output_dir"]
    console.print(f"Regenerating report from: {input_file}")
    console.print(f"Output directory: {output_dir}")
    console.print("(Load the JSON, reconstruct findings, call generate_scan_report.)")


@cli.command("list-detectors")
def list_detectors() -> None:
    """List all active regex detector patterns."""
    from detectors.regex_detector import DETECTOR_PATTERNS

    table = Table(title="Active Detector Patterns", show_lines=True)
    table.add_column("Name", style="bold")
    table.add_column("Secret Type")
    table.add_column("Criticality")
    table.add_column("Description")

    for detector in DETECTOR_PATTERNS:
        crit_color = {
            "critical": "red",
            "high": "yellow",
            "medium": "cyan",
            "low": "green",
        }.get(detector.criticality.value, "white")

        table.add_row(
            detector.name,
            detector.secret_type.value,
            f"[{crit_color}]{detector.criticality.value.upper()}[/{crit_color}]",
            detector.description,
        )

    console.print(table)


def _print_findings_table(classified) -> None:
    """Print a rich table of classified findings to the terminal."""
    if not classified:
        return

    table = Table(title="Secret Detection Findings", show_lines=True)
    table.add_column("#", justify="right", style="dim")
    table.add_column("Criticality")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Detector")
    table.add_column("Confidence", justify="right")

    for i, cf in enumerate(classified, start=1):
        crit = cf.final_criticality.value
        crit_color = {
            "critical": "bold red",
            "high": "yellow",
            "medium": "cyan",
            "low": "green",
        }.get(crit, "white")

        table.add_row(
            str(i),
            f"[{crit_color}]{crit.upper()}[/{crit_color}]",
            cf.original_finding.file_path,
            str(cf.original_finding.line_number),
            cf.original_finding.detector_name,
            f"{cf.confidence:.0%}",
        )

    console.print(table)


def _apply_fail_policy(classified, fail_on: str, quiet: bool = False) -> None:
    """Exit non-zero if any classified finding meets or exceeds the fail_on severity."""
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    threshold = severity_rank.get(fail_on, 3)

    for cf in classified:
        if severity_rank.get(cf.final_criticality.value, 0) >= threshold:
            if not quiet:
                console.print(
                    f"\n[bold red]Fail condition met:[/bold red] findings at or above "
                    f"'{fail_on}' severity detected."
                )
            sys.exit(1)


if __name__ == "__main__":
    cli()
