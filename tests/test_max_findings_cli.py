import json

from click.testing import CliRunner

import secret_leak_sentinel_cli as app


def test_scan_path_json_truncated_with_cap(monkeypatch, tmp_path):
    test_dir = tmp_path / "repo"
    test_dir.mkdir()

    monkeypatch.setattr(
        app,
        "_scan_path_impl",
        lambda _p: [
            {"id": 1, "secret": "a"},
            {"id": 2, "secret": "b"},
            {"id": 3, "secret": "c"},
        ],
    )

    runner = CliRunner()
    result = runner.invoke(
        app.cli,
        ["scan-path", str(test_dir), "--json-output", "--max-findings", "2"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["count"] == 2
    assert payload["max_findings"] == 2
    assert payload["truncated"] is True
    assert len(payload["findings"]) == 2


def test_scan_staged_json_not_truncated_without_cap(monkeypatch):
    monkeypatch.setattr(app, "_scan_staged_impl", lambda: [{"id": "x"}])

    runner = CliRunner()
    result = runner.invoke(app.cli, ["scan-staged", "--json-output"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["count"] == 1
    assert payload["max_findings"] is None
    assert payload["truncated"] is False
