from __future__ import annotations

from click.testing import CliRunner

from secret_leak_sentinel_cli import cli


def test_scan_path_exit_code_threshold_controls_failure(monkeypatch, tmp_path):
    target = tmp_path / "repo"
    target.mkdir()

    def fake_scan_path(_path):
        return [
            {
                "severity": "low",
                "file": "a.txt",
                "line": 1,
                "message": "low finding",
            },
            {
                "severity": "high",
                "file": "b.txt",
                "line": 2,
                "message": "high finding",
            },
        ]

    monkeypatch.setattr("secret_leak_sentinel_cli.scanner_scan_path", fake_scan_path)

    runner = CliRunner()

    res_fail = runner.invoke(cli, ["scan-path", str(target), "--exit-code-threshold", "medium"])
    assert res_fail.exit_code == 1

    res_pass = runner.invoke(cli, ["scan-path", str(target), "--exit-code-threshold", "critical"])
    assert res_pass.exit_code == 0
