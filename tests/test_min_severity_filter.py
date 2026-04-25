import json

from click.testing import CliRunner

from secret_leak_sentinel_cli import cli


def test_scan_path_min_severity_filters_before_output(monkeypatch, tmp_path):
    sample_findings = [
        {"id": "a", "severity": "low"},
        {"id": "b", "severity": "medium"},
        {"id": "c", "severity": "high"},
        {"id": "d", "severity": "critical"},
    ]

    def fake_scan_path(_path):
        return sample_findings

    monkeypatch.setattr("secret_leak_sentinel_cli.scanner_scan_path", fake_scan_path)

    runner = CliRunner()
    scan_target = tmp_path / "repo"
    scan_target.mkdir()
    out_file = tmp_path / "out.json"

    result = runner.invoke(
        cli,
        ["scan-path", str(scan_target), "--min-severity", "high", "--json-output", str(out_file)],
    )

    assert result.exit_code == 0

    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert [f["id"] for f in payload] == ["c", "d"]

    stdout_payload = json.loads(result.output)
    assert [f["id"] for f in stdout_payload] == ["c", "d"]
