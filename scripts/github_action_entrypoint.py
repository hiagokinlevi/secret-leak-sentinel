"""Validated entrypoint for the Marketplace-ready GitHub Action."""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path


SUPPORTED_COMMANDS = {
    "list-detectors",
    "scan-file",
    "scan-git",
    "scan-git-history",
    "scan-path",
    "validate-policy",
}

FORBIDDEN_ARG_TOKENS = {
    "--entropy",
    "--no-entropy",
    "--entropy-threshold",
    "--fail-on",
    "--output-dir",
    "--policy-profile",
}
REPORT_PATTERNS = {
    "report_markdown": "secret_scan_*.md",
    "report_csv": "secret_scan_*.csv",
    "report_html": "secret_scan_*.html",
}


def parse_action_args(raw_args: str) -> list[str]:
    """Split a GitHub Action input string into CLI tokens."""
    try:
        tokens = shlex.split(raw_args, posix=True)
    except ValueError as exc:
        raise ValueError(f"Unable to parse args: {exc}") from exc

    forbidden = [token for token in tokens if token in FORBIDDEN_ARG_TOKENS]
    if forbidden:
        joined = ", ".join(sorted(set(forbidden)))
        raise ValueError(
            f"Do not pass {joined} in args; use the dedicated action inputs instead."
        )
    return tokens


def validate_command(command: str) -> str:
    """Ensure the requested subcommand is explicitly supported."""
    normalized = command.strip()
    if not normalized:
        raise ValueError("Action input 'command' is required.")
    if normalized not in SUPPORTED_COMMANDS:
        supported = ", ".join(sorted(SUPPORTED_COMMANDS))
        raise ValueError(f"Unsupported command '{normalized}'. Supported commands: {supported}")
    return normalized


def resolve_working_directory(raw_workdir: str) -> Path:
    """Resolve the working directory against the GitHub Actions workspace."""
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd()))
    path = Path(raw_workdir)
    if not path.is_absolute():
        path = workspace / path
    resolved = path.resolve()
    try:
        resolved.relative_to(workspace.resolve())
    except ValueError as exc:
        raise ValueError(
            "working-directory must stay within GITHUB_WORKSPACE."
        ) from exc
    return resolved


def resolve_output_directory(raw_output_dir: str, workdir: Path) -> Path:
    """Resolve the report output directory relative to the working directory."""
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd())).resolve()
    path = Path(raw_output_dir)
    if not path.is_absolute():
        path = workdir / path
    resolved = path.resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(
            "output-dir must stay within GITHUB_WORKSPACE."
        ) from exc
    return resolved


def build_command(
    *,
    subcommand: str,
    raw_args: str,
    output_dir: Path,
    fail_on: str,
    entropy_enabled: bool,
    entropy_threshold: float,
    policy_profile: str,
) -> list[str]:
    """Construct the validated secret-leak-sentinel command."""
    command = validate_command(subcommand)
    extra_args = parse_action_args(raw_args)
    entropy_flag = "--entropy" if entropy_enabled else "--no-entropy"

    return [
        "secret-leak-sentinel",
        "--output-dir",
        str(output_dir),
        "--fail-on",
        fail_on,
        "--entropy-threshold",
        str(entropy_threshold),
        "--policy-profile",
        policy_profile,
        entropy_flag,
        command,
        *extra_args,
    ]


def discover_report_outputs(output_dir: Path) -> dict[str, str]:
    """Return the newest report path for each known report extension."""
    results = {key: "" for key in REPORT_PATTERNS}
    if not output_dir.exists():
        return results

    for key, pattern in REPORT_PATTERNS.items():
        candidates = sorted(output_dir.glob(pattern), key=lambda item: item.stat().st_mtime)
        if candidates:
            results[key] = str(candidates[-1].resolve())
    return results


def write_github_outputs(outputs: dict[str, str]) -> None:
    """Append action outputs when running inside GitHub Actions."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with Path(output_path).open("a", encoding="utf-8") as handle:
        for key, value in outputs.items():
            handle.write(f"{key}={value}\n")


def _parse_bool(raw_value: str) -> bool:
    """Parse a string GitHub Action input into a strict boolean value."""
    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(
        "Boolean inputs must be one of: true, false, yes, no, on, off, 1, 0."
    )


def main(argv: list[str] | None = None) -> int:
    """Run the requested CLI command and expose generated report paths."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command", required=True, help="Supported subcommand to run.")
    parser.add_argument("--args", default="", help="Additional subcommand arguments.")
    parser.add_argument(
        "--output-dir",
        default="./scan-results",
        help="Directory where reports should be written.",
    )
    parser.add_argument("--fail-on", default="high", help="Minimum severity that fails the run.")
    parser.add_argument(
        "--entropy-enabled",
        default="true",
        help="Whether entropy detection is enabled.",
    )
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=4.5,
        help="Entropy threshold passed to the CLI root option.",
    )
    parser.add_argument(
        "--policy-profile",
        default="default",
        help="Policy profile passed to the CLI root option.",
    )
    parser.add_argument(
        "--working-directory",
        default=".",
        help="Directory where the CLI command should run.",
    )
    parsed = parser.parse_args(argv)

    try:
        workdir = resolve_working_directory(parsed.working_directory)
        output_dir = resolve_output_directory(parsed.output_dir, workdir)
        command = build_command(
            subcommand=parsed.command,
            raw_args=parsed.args,
            output_dir=output_dir,
            fail_on=parsed.fail_on,
            entropy_enabled=_parse_bool(parsed.entropy_enabled),
            entropy_threshold=parsed.entropy_threshold,
            policy_profile=parsed.policy_profile,
        )
    except ValueError as exc:
        print(f"Action input error: {exc}", file=sys.stderr)
        return 2

    output_dir.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(command, cwd=workdir, check=False)
    outputs = {
        "command": shlex.join(command),
        "working_directory": str(workdir),
        "output_directory": str(output_dir),
        "exit_code": str(completed.returncode),
        **discover_report_outputs(output_dir),
    }
    write_github_outputs(outputs)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
