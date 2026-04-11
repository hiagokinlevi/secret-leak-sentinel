from __future__ import annotations

import sys
import types
from pathlib import Path

from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.main import cli


def _install_dummy_git(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "git", types.ModuleType("git"))


class DummyFinding:
    def __init__(self) -> None:
        self.commit_sha = "deadbeefcafebabe"
        self.commit_author = "alice@example.com"
        self.file_path = "config.py"
        self.line_number = 3
        self.rule_id = "AWS_ACCESS_KEY"
        self.evidence = "AKIA...masked"


class DummyReport:
    def __init__(self, findings):
        self.findings = findings

    def summary(self) -> str:
        return "History scan: summary"

    def to_dict(self) -> dict:
        return {
            "total_findings": len(self.findings),
            "findings": [
                {
                    "commit_sha": f.commit_sha[:12],
                    "commit_author": f.commit_author,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "rule_id": f.rule_id,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
        }


def test_scan_git_history_uses_cli_table(monkeypatch):
    _install_dummy_git(monkeypatch)

    class DummyScanner:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def scan(self):
            return DummyReport([])

    monkeypatch.setattr("scanners.git_history_scanner.GitHistoryScanner", DummyScanner)

    runner = CliRunner()
    result = runner.invoke(cli, ["scan-git-history", "--repo", "."])

    assert result.exit_code == 0
    assert "Scanning git history:" in result.output
    assert "No historical secrets detected." in result.output


def test_scan_git_history_exits_non_zero_when_findings(monkeypatch):
    _install_dummy_git(monkeypatch)

    class DummyScanner:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def scan(self):
            return DummyReport([DummyFinding()])

    monkeypatch.setattr("scanners.git_history_scanner.GitHistoryScanner", DummyScanner)

    runner = CliRunner()
    result = runner.invoke(cli, ["scan-git-history", "--repo", "."])

    assert result.exit_code == 1
    assert "Git History Findings" in result.output
    assert "deadbeefcafe" in result.output


def test_scan_git_history_json_output(monkeypatch):
    _install_dummy_git(monkeypatch)

    class DummyScanner:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def scan(self):
            return DummyReport([DummyFinding()])

    monkeypatch.setattr("scanners.git_history_scanner.GitHistoryScanner", DummyScanner)

    runner = CliRunner()
    result = runner.invoke(cli, ["scan-git-history", "--repo", ".", "--json-output"])

    assert result.exit_code == 1
    assert '"total_findings": 1' in result.output


def test_scan_git_history_reports_missing_gitpython(monkeypatch):
    original_import = __import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "git":
            raise ImportError("missing gitpython")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr("builtins.__import__", fake_import)

    runner = CliRunner()
    result = runner.invoke(cli, ["scan-git-history", "--repo", "."])

    assert result.exit_code == 2
    assert "requires GitPython" in result.output
