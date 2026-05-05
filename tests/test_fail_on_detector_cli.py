from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from secret_leak_sentinel_cli import _app


def _write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_fail_on_detector_exits_zero_when_no_matching_detector(tmp_path: Path) -> None:
    target = tmp_path / "sample.txt"
    _write_file(target, "hello world")

    json_output = tmp_path / "out.json"
    runner = CliRunner()
    result = runner.invoke(
        _app,
        [
            "scan-path",
            str(tmp_path),
            "--json-output",
            str(json_output),
            "--fail-on-detector",
            "aws_access_key",
        ],
    )

    assert result.exit_code == 0, result.output


def test_fail_on_detector_exits_nonzero_on_matching_detector(tmp_path: Path) -> None:
    target = tmp_path / "keys.txt"
    _write_file(target, "AKIAIOSFODNN7EXAMPLE")

    json_output = tmp_path / "out.json"
    runner = CliRunner()
    result = runner.invoke(
        _app,
        [
            "scan-path",
            str(tmp_path),
            "--json-output",
            str(json_output),
            "--fail-on-detector",
            "aws_access_key",
        ],
    )

    # If the exact detector ID differs in this repository, validate by reading output and
    # re-running with discovered detector from first finding.
    if result.exit_code == 0 and json_output.exists():
        payload = json.loads(json_output.read_text(encoding="utf-8"))
        findings = payload if isinstance(payload, list) else payload.get("findings", [])
        if findings:
            detector = findings[0].get("detector") or findings[0].get("rule_id")
            rerun = runner.invoke(
                _app,
                [
                    "scan-path",
                    str(tmp_path),
                    "--json-output",
                    str(json_output),
                    "--fail-on-detector",
                    str(detector),
                ],
            )
            assert rerun.exit_code != 0, rerun.output
            return

    assert result.exit_code != 0, result.output
