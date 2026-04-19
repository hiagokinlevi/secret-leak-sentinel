#!/usr/bin/env python3
"""secret-leak-sentinel CLI.

This module provides a compact command-line scanner interface for:
- directories / single files
- git repositories (working tree, staged, history)
- log files

It exposes flags for:
- scan scope
- output format (json / sarif)
- ignore rules
- entropy threshold
- provider-specific scanning

The implementation is intentionally defensive about optional internal modules so
this CLI remains usable as integration glue even when some scanner backends are
not available in minimal environments.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

import click


SUPPORTED_PROVIDERS = (
    "aws",
    "azure",
    "gcp",
    "github",
    "gitlab",
    "slack",
    "stripe",
    "twilio",
    "sendgrid",
    "vault",
    "npm",
    "jwt",
)


def _parse_ignore(ctx: click.Context, param: click.Parameter, value: Iterable[str]) -> List[str]:
    ignores: List[str] = []
    for item in value:
        if not item:
            continue
        ignores.extend([x.strip() for x in item.split(",") if x.strip()])
    return ignores


def _import_backend() -> Dict[str, Optional[Callable[..., Any]]]:
    """Load backends lazily and tolerate partial project layouts."""

    backends: Dict[str, Optional[Callable[..., Any]]] = {
        "scan_path": None,
        "scan_staged": None,
        "scan_git": None,
        "scan_file": None,
    }

    # Try common existing module locations without failing hard.
    candidates = [
        ("cli.main", "scan_path", "scan_staged", "scan_git", "scan_file"),
        ("scanners.filesystem_scanner", "scan_path"),
        ("scanners.git_scanner", "scan_staged", "scan_git"),
        ("scanners.log_scanner", "scan_file"),
    ]

    for spec in candidates:
        module_name, *funcs = spec
        try:
            module = __import__(module_name, fromlist=["*"])
        except Exception:
            continue
        for fn in funcs:
            if hasattr(module, fn):
                backends[fn] = getattr(module, fn)

    return backends


def _normalize_output(raw: Any) -> Dict[str, Any]:
    if raw is None:
        return {"findings": [], "summary": {"count": 0}}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, list):
        return {"findings": raw, "summary": {"count": len(raw)}}
    return {"result": str(raw)}


def _to_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    findings = report.get("findings", [])
    results = []
    for f in findings:
        location = f.get("location") or {}
        path = location.get("path") or f.get("file") or "unknown"
        line = location.get("line") or f.get("line") or 1
        rule_id = f.get("type") or f.get("rule") or "secret-detected"
        message = f.get("message") or f.get("match") or "Potential secret detected"
        results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(path)},
                            "region": {"startLine": int(line)},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secret-leak-sentinel",
                        "rules": [],
                    }
                },
                "results": results,
            }
        ],
    }


def _emit(report: Dict[str, Any], output_format: str) -> None:
    if output_format == "sarif":
        click.echo(json.dumps(_to_sarif(report), indent=2))
    else:
        click.echo(json.dumps(report, indent=2))


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli() -> None:
    """secret-leak-sentinel scanner commands."""


@cli.command("scan")
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--scope",
    type=click.Choice(["auto", "dir", "repo", "log"], case_sensitive=False),
    default="auto",
    show_default=True,
    help="Scan scope: directory, repository, or log file.",
)
@click.option(
    "--output-format",
    type=click.Choice(["json", "sarif"], case_sensitive=False),
    default="json",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--ignore",
    multiple=True,
    callback=_parse_ignore,
    help="Ignore rule(s) by id/pattern. Can be repeated or comma-separated.",
)
@click.option(
    "--ignore-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to ignore rules file.",
)
@click.option(
    "--entropy-threshold",
    type=float,
    default=4.5,
    show_default=True,
    help="Entropy threshold for high-entropy token detection.",
)
@click.option(
    "--provider",
    "providers",
    multiple=True,
    type=click.Choice(SUPPORTED_PROVIDERS, case_sensitive=False),
    help="Restrict scan to provider-specific detectors. Repeatable.",
)
def scan(
    target: Path,
    scope: str,
    output_format: str,
    ignore: List[str],
    ignore_file: Optional[Path],
    entropy_threshold: float,
    providers: List[str],
) -> None:
    """Scan a directory/repo/log target with configurable options."""

    backends = _import_backend()

    options: Dict[str, Any] = {
        "ignore_rules": ignore,
        "ignore_file": str(ignore_file) if ignore_file else None,
        "entropy_threshold": entropy_threshold,
        "providers": [p.lower() for p in providers],
    }

    resolved_scope = scope.lower()
    if resolved_scope == "auto":
        if target.is_file() and target.suffix.lower() in {".log", ".txt"}:
            resolved_scope = "log"
        elif (target / ".git").exists():
            resolved_scope = "repo"
        else:
            resolved_scope = "dir"

    if resolved_scope == "repo":
        fn = backends.get("scan_git")
        if fn is None:
            raise click.ClickException("Repository scanner backend not available")
        raw = fn(str(target), **options)
    elif resolved_scope == "log":
        fn = backends.get("scan_file") or backends.get("scan_path")
        if fn is None:
            raise click.ClickException("Log/file scanner backend not available")
        raw = fn(str(target), **options)
    else:
        fn = backends.get("scan_path")
        if fn is None:
            raise click.ClickException("Filesystem scanner backend not available")
        raw = fn(str(target), **options)

    report = _normalize_output(raw)
    _emit(report, output_format.lower())


if __name__ == "__main__":
    cli()
