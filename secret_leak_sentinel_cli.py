from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

import click

from cli.main import cli as _root_cli


def _filter_findings_by_rule_ids(findings: Sequence[dict], exclude_rule_ids: Optional[Iterable[str]]) -> List[dict]:
    """Return findings with any excluded detector rule IDs removed."""
    excluded = {rid.strip() for rid in (exclude_rule_ids or []) if rid and rid.strip()}
    if not excluded:
        return list(findings)
    filtered: List[dict] = []
    for finding in findings:
        rule_id = finding.get("rule_id") or finding.get("detector_rule_id")
        if rule_id in excluded:
            continue
        filtered.append(finding)
    return filtered


def _apply_runtime_exclusions_to_result(result: dict, exclude_rule_ids: Optional[Iterable[str]]) -> dict:
    """Apply runtime exclusions immediately before output/report generation."""
    if not isinstance(result, dict):
        return result
    findings = result.get("findings")
    if not isinstance(findings, list):
        return result
    filtered = _filter_findings_by_rule_ids(findings, exclude_rule_ids)
    if len(filtered) == len(findings):
        return result
    updated = dict(result)
    updated["findings"] = filtered
    # Keep common counters coherent when present.
    if "total_findings" in updated:
        updated["total_findings"] = len(filtered)
    if "finding_count" in updated:
        updated["finding_count"] = len(filtered)
    return updated


@click.group(cls=click.Group, invoke_without_command=False)
def cli() -> None:
    """secret-leak-sentinel CLI."""


# Delegate all existing commands from the project CLI.
for _name, _cmd in _root_cli.commands.items():
    cli.add_command(_cmd, _name)


def _patch_scan_command(name: str) -> None:
    cmd = cli.commands.get(name)
    if cmd is None:
        return

    original_callback = cmd.callback
    if original_callback is None:
        return

    @click.option(
        "--exclude-rule-id",
        "exclude_rule_ids",
        multiple=True,
        help="Detector rule ID to exclude at runtime. Repeatable.",
    )
    def _wrapped_option(**kwargs):
        return kwargs

    # Rebuild command params by appending new option.
    cmd.params.append(_wrapped_option.__click_params__[0])

    def _wrapped_callback(*args, **kwargs):
        exclude_rule_ids = kwargs.pop("exclude_rule_ids", ())
        result = original_callback(*args, **kwargs)
        # If callback already emits output and returns None, we cannot rewrite payload.
        # For dict-like return flows, normalize before renderers consume it.
        if isinstance(result, dict):
            result = _apply_runtime_exclusions_to_result(result, exclude_rule_ids)

            # Best-effort JSON output rewrite for callbacks that pass through output paths.
            json_output = kwargs.get("json_output") or result.get("json_output")
            if json_output:
                try:
                    Path(json_output).write_text(json.dumps(result, indent=2), encoding="utf-8")
                except Exception:
                    pass
        return result

    cmd.callback = _wrapped_callback


for _scan_cmd in ("scan-path", "scan-staged", "scan-git"):
    _patch_scan_command(_scan_cmd)


if __name__ == "__main__":
    cli()
