from pathlib import Path

from click.testing import CliRunner

from secret_leak_sentinel_cli import cli


def test_scan_path_include_hidden_flag_respects_default_and_opt_in(tmp_path: Path):
    # visible files
    (tmp_path / "visible.env").write_text("API_KEY=abc", encoding="utf-8")
    (tmp_path / "visible.txt").write_text("ignore by ext", encoding="utf-8")

    # hidden files/dirs
    (tmp_path / ".hidden.env").write_text("TOKEN=secret", encoding="utf-8")
    (tmp_path / ".secrets").mkdir()
    (tmp_path / ".secrets" / "nested.env").write_text("PASSWORD=secret", encoding="utf-8")

    runner = CliRunner()

    # default: hidden excluded, extension filtering still applies
    default_result = runner.invoke(
        cli,
        ["scan-path", str(tmp_path), "--ext", ".env"],
    )
    assert default_result.exit_code == 0, default_result.output
    assert "visible.env" in default_result.output
    assert ".hidden.env" not in default_result.output
    assert "nested.env" not in default_result.output
    assert "visible.txt" not in default_result.output

    # opt-in: hidden included, and extension filtering still applies
    include_result = runner.invoke(
        cli,
        ["scan-path", str(tmp_path), "--ext", ".env", "--include-hidden"],
    )
    assert include_result.exit_code == 0, include_result.output
    assert "visible.env" in include_result.output
    assert ".hidden.env" in include_result.output
    assert "nested.env" in include_result.output
    assert "visible.txt" not in include_result.output
