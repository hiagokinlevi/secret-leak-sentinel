from pathlib import Path

from click.testing import CliRunner

from secret_leak_sentinel_cli import cli


def test_scan_path_no_default_excludes_flag_changes_behavior(monkeypatch, tmp_path: Path):
    runner = CliRunner()
    captured = {}

    def fake_scan_path(path, excludes=None, use_default_excludes=True):
        captured["path"] = path
        captured["excludes"] = excludes
        captured["use_default_excludes"] = use_default_excludes
        return []

    monkeypatch.setattr("secret_leak_sentinel_cli.scan_path", fake_scan_path)

    result_default = runner.invoke(cli, ["scan-path", str(tmp_path)])
    assert result_default.exit_code == 0, result_default.output
    assert captured["use_default_excludes"] is True

    result_disabled = runner.invoke(cli, ["scan-path", str(tmp_path), "--no-default-excludes"])
    assert result_disabled.exit_code == 0, result_disabled.output
    assert captured["use_default_excludes"] is False
