from pathlib import Path

from click.testing import CliRunner

from secret_leak_sentinel_cli import cli


def test_scan_path_allowed_extension_filters_files_after_excludes(tmp_path: Path):
    src = tmp_path / "repo"
    src.mkdir()

    py_file = src / "app.py"
    py_file.write_text("token = 'sk_live_1234567890abcdef'\n", encoding="utf-8")

    txt_file = src / "notes.txt"
    txt_file.write_text("token = 'sk_live_1234567890abcdef'\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan-path",
            str(src),
            "--allowed-extension",
            ".py",
            "--json-output",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "app.py" in result.output
    assert "notes.txt" not in result.output
