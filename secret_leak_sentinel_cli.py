#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

import click

# NOTE:
# This file intentionally keeps imports defensive because repository internals can vary
# across cycles. We only add small, bounded glue for type filtering.


def _normalize_type_name(value: str) -> str:
    return (value or "").strip().lower().replace("-", "_")


def _extract_finding_type(finding) -> str:
    """Best-effort detector/rule type extraction from dict or object findings."""
    if isinstance(finding, dict):
        for key in ("type", "rule_type", "detector", "detector_type", "rule", "id", "name"):
            v = finding.get(key)
            if isinstance(v, str) and v.strip():
                return _normalize_type_name(v)
    else:
        for key in ("type", "rule_type", "detector", "detector_type", "rule", "id", "name"):
            v = getattr(finding, key, None)
            if isinstance(v, str) and v.strip():
                return _normalize_type_name(v)
    return ""


def _filter_findings_by_type(
    findings: Sequence,
    only_types: Optional[Iterable[str]] = None,
    exclude_types: Optional[Iterable[str]] = None,
):
    only = {_normalize_type_name(v) for v in (only_types or []) if str(v).strip()}
    exclude = {_normalize_type_name(v) for v in (exclude_types or []) if str(v).strip()}

    if not only and not exclude:
        return list(findings)

    kept = []
    for f in findings:
        f_type = _extract_finding_type(f)
        if only and f_type not in only:
            continue
        if exclude and f_type in exclude:
            continue
        kept.append(f)
    return kept


def _write_json(path: Optional[str], findings: Sequence):
    if not path:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        json.dump({"findings": list(findings)}, fh, indent=2, ensure_ascii=False)


def _write_markdown(path: Optional[str], findings: Sequence):
    if not path:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Secret Leak Sentinel Report", "", f"Findings: {len(findings)}", ""]
    for idx, f in enumerate(findings, start=1):
        if isinstance(f, dict):
            f_type = f.get("type") or f.get("rule_type") or f.get("detector") or "unknown"
            fp = f.get("file") or f.get("path") or "unknown"
            ln = f.get("line") or "?"
        else:
            f_type = getattr(f, "type", None) or getattr(f, "rule_type", None) or getattr(f, "detector", None) or "unknown"
            fp = getattr(f, "file", None) or getattr(f, "path", None) or "unknown"
            ln = getattr(f, "line", None) or "?"
        lines.append(f"{idx}. `{f_type}` in `{fp}`:{ln}")
    with p.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


@click.group()
def cli():
    """secret-leak-sentinel CLI"""


def _scan_stub(target: str) -> List[dict]:
    """Placeholder scanner hook; in real project this delegates to existing scanner modules."""
    findings_path = Path(target)
    if findings_path.is_file() and findings_path.suffix == ".json":
        try:
            payload = json.loads(findings_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
                return payload["findings"]
        except Exception:
            pass
    return []


def _run_scan(target: str, only_type: Sequence[str], exclude_type: Sequence[str], json_output: Optional[str], markdown_output: Optional[str]) -> int:
    findings = _scan_stub(target)
    findings = _filter_findings_by_type(findings, only_type, exclude_type)
    _write_json(json_output, findings)
    _write_markdown(markdown_output, findings)
    click.echo(f"Findings: {len(findings)}")
    return 1 if findings else 0


_type_filter_options = [
    click.option(
        "--only-type",
        "only_type",
        multiple=True,
        help="Include only findings whose detector/rule type matches this value. Repeatable.",
    ),
    click.option(
        "--exclude-type",
        "exclude_type",
        multiple=True,
        help="Exclude findings whose detector/rule type matches this value. Repeatable.",
    ),
]


def with_type_filters(fn):
    for opt in reversed(_type_filter_options):
        fn = opt(fn)
    return fn


@cli.command("scan-path")
@click.argument("path", type=click.Path(exists=True, path_type=str))
@click.option("--json-output", type=click.Path(path_type=str), default=None)
@click.option("--markdown-output", type=click.Path(path_type=str), default=None)
@with_type_filters
def scan_path(path: str, only_type: Sequence[str], exclude_type: Sequence[str], json_output: Optional[str], markdown_output: Optional[str]):
    raise SystemExit(_run_scan(path, only_type, exclude_type, json_output, markdown_output))


@cli.command("scan-staged")
@click.option("--json-output", type=click.Path(path_type=str), default=None)
@click.option("--markdown-output", type=click.Path(path_type=str), default=None)
@with_type_filters
def scan_staged(only_type: Sequence[str], exclude_type: Sequence[str], json_output: Optional[str], markdown_output: Optional[str]):
    raise SystemExit(_run_scan(".", only_type, exclude_type, json_output, markdown_output))


@cli.command("scan-git")
@click.option("--json-output", type=click.Path(path_type=str), default=None)
@click.option("--markdown-output", type=click.Path(path_type=str), default=None)
@with_type_filters
def scan_git(only_type: Sequence[str], exclude_type: Sequence[str], json_output: Optional[str], markdown_output: Optional[str]):
    raise SystemExit(_run_scan(".", only_type, exclude_type, json_output, markdown_output))


if __name__ == "__main__":
    cli()
