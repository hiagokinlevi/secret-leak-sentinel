from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import click

from cli.app import app as _app


# NOTE:
# This thin wrapper exists so local invocation via `python secret_leak_sentinel_cli.py`
# works. We extend the underlying Click app in-place with a small compatibility layer
# for `--fail-on-detector` without changing core detection logic.


def _parse_detector_filters(values: tuple[str, ...]) -> set[str]:
    parsed: set[str] = set()
    for raw in values:
        for part in raw.split(","):
            token = part.strip()
            if token:
                parsed.add(token)
    return parsed


def _finding_detector_id(finding: dict) -> str | None:
    return finding.get("detector") or finding.get("rule_id")


def _load_findings_from_json_output(path_value: str | None) -> list[dict]:
    if not path_value:
        return []
    p = Path(path_value)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []

    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        findings = data.get("findings")
        if isinstance(findings, list):
            return [x for x in findings if isinstance(x, dict)]
    return []


def _has_detector_match(findings: Iterable[dict], filters: set[str]) -> bool:
    if not filters:
        return False
    for f in findings:
        det = _finding_detector_id(f)
        if det and det in filters:
            return True
    return False


def _patch_command_with_fail_on_detector(command_name: str) -> None:
    cmd = _app.commands.get(command_name)
    if cmd is None:
        return

    # Prevent duplicate patching.
    if any(getattr(p, "name", None) == "fail_on_detector" for p in cmd.params):
        return

    option = click.Option(
        ["--fail-on-detector"],
        multiple=True,
        help=(
            "Detector ID(s) that should cause a non-zero exit when present in findings. "
            "Can be repeated or provided as a comma-separated list."
        ),
    )
    cmd.params.append(option)

    original_callback = cmd.callback

    def wrapped_callback(*args, **kwargs):
        fail_on_detector_values = kwargs.pop("fail_on_detector", ()) or ()
        detector_filters = _parse_detector_filters(tuple(fail_on_detector_values))

        try:
            result = original_callback(*args, **kwargs)
        except SystemExit as e:
            # If command already failed for other reasons, preserve behavior.
            if e.code not in (0, None):
                raise
            result = None

        if detector_filters:
            findings = _load_findings_from_json_output(kwargs.get("json_output"))
            if _has_detector_match(findings, detector_filters):
                raise click.ClickException(
                    "Findings matched --fail-on-detector filters: "
                    + ", ".join(sorted(detector_filters))
                )

        return result

    cmd.callback = wrapped_callback


for _name in ("scan-path", "scan-staged", "scan-git"):
    _patch_command_with_fail_on_detector(_name)


if __name__ == "__main__":
    _app()
