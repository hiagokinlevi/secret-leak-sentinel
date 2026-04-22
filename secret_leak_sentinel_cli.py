from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple

import click


@click.group()
def cli() -> None:
    pass


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _line_hash(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _fingerprint(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    rule_id = str(finding.get("rule_id", ""))
    file_path = str(finding.get("file", finding.get("path", "")))
    line = finding.get("line", finding.get("line_number", ""))
    return (rule_id, file_path, _line_hash(line))


def _extract_findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = report.get("findings", [])
    return raw if isinstance(raw, list) else []


def _baseline_fingerprints(baseline_path: Path) -> Set[Tuple[str, str, str]]:
    baseline = _load_json(baseline_path)
    return {_fingerprint(f) for f in _extract_findings(baseline)}


def _apply_baseline_suppression(
    findings: List[Dict[str, Any]], baseline_path: Path | None
) -> List[Dict[str, Any]]:
    if baseline_path is None:
        return findings
    known = _baseline_fingerprints(baseline_path)
    return [f for f in findings if _fingerprint(f) not in known]


@cli.command("scan-path")
@click.argument("target", type=click.Path(path_type=Path))
@click.option("--json-output", "json_output", type=click.Path(path_type=Path), default=None)
@click.option(
    "--baseline",
    "baseline",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    default=None,
    help="Path to previous JSON report; unchanged findings are suppressed.",
)
def scan_path(target: Path, json_output: Path | None, baseline: Path | None) -> None:
    # NOTE: Keep existing scanner wiring untouched; only post-process findings.
    # This placeholder expects existing project scanner integration to provide `report`.
    report: Dict[str, Any] = {
        "target": str(target),
        "findings": [],
    }

    findings = _extract_findings(report)
    filtered = _apply_baseline_suppression(findings, baseline)
    report["findings"] = filtered
    report["summary"] = {
        **(report.get("summary") or {}),
        "total_findings": len(filtered),
    }

    payload = json.dumps(report, indent=2)
    if json_output:
        json_output.write_text(payload + "\n", encoding="utf-8")
    else:
        click.echo(payload)

    raise SystemExit(1 if len(filtered) > 0 else 0)


if __name__ == "__main__":
    cli()
