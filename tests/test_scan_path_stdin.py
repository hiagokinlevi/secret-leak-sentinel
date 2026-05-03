from __future__ import annotations

import json

from click.testing import CliRunner

from cli.main import cli


def test_scan_path_from_stdin_emits_finding_and_nonzero_exit(tmp_path):
    runner = CliRunner()
    output_file = tmp_path / "report.json"

    # Typical AWS Access Key ID shape to trigger detector
    stdin_payload = "build log line: leaked key AKIA1234567890ABCD"

    result = runner.invoke(
        cli,
        [
            "scan-path",
            "--from-stdin",
            "--stdin-filename",
            "build.log",
            "--json-output",
            str(output_file),
        ],
        input=stdin_payload,
    )

    assert result.exit_code == 1
    assert output_file.exists()

    report = json.loads(output_file.read_text(encoding="utf-8"))
    assert report["summary"]["total_findings"] >= 1
    assert any(f.get("file_path") == "build.log" for f in report["findings"])
