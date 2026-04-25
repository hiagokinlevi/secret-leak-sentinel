from __future__ import annotations

from click.testing import CliRunner

from cli.commands import cli


def test_scan_staged_writes_output_file(monkeypatch, tmp_path):
    def _fake_scan_staged_changes():
        return {"findings": [{"id": "s1", "secret": "abc"}]}

    monkeypatch.setattr("cli.commands.scan_staged_changes", _fake_scan_staged_changes)

    out_file = tmp_path / "staged-report.json"
    runner = CliRunner()
    result = runner.invoke(cli, ["scan-staged", "--json-output", "--output-file", str(out_file)])

    assert result.exit_code == 0
    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8").strip() != ""


def test_scan_git_writes_output_file(monkeypatch, tmp_path):
    def _fake_scan_git_history():
        return {"findings": [{"id": "g1", "secret": "xyz"}]}

    monkeypatch.setattr("cli.commands.scan_git_history", _fake_scan_git_history)

    out_file = tmp_path / "git-report.json"
    runner = CliRunner()
    result = runner.invoke(cli, ["scan-git", "--json-output", "--output-file", str(out_file)])

    assert result.exit_code == 0
    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8").strip() != ""
