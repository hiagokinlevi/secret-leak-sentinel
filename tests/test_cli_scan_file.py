from __future__ import annotations

import sys
from pathlib import Path

from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.main import cli


_FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"


def test_scan_file_reports_clean_file(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("print('hello')\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan-file", str(target)])

    assert result.exit_code == 0
    assert "No secrets detected." in result.output


def test_scan_file_exits_non_zero_for_detected_secret(tmp_path):
    target = tmp_path / "config.py"
    target.write_text(f'AWS_ACCESS_KEY_ID = "{_FAKE_AWS}"\n', encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan-file", str(target)])

    assert result.exit_code == 1
    assert "Secret Detection Findings" in result.output
    assert "config.py" in result.output


def test_scan_file_patch_mode_ignores_deleted_secret(tmp_path):
    patch = tmp_path / "removal.diff"
    patch.write_text(
        "\n".join(
            [
                "diff --git a/app.py b/app.py",
                "index 1111111..2222222 100644",
                "--- a/app.py",
                "+++ b/app.py",
                "@@ -1 +1 @@",
                f'-AWS_ACCESS_KEY_ID = "{_FAKE_AWS}"',
                '+print("secret removed")',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan-file", "--patch-mode", str(patch)])

    assert result.exit_code == 0
    assert "No secrets detected." in result.output


def test_scan_file_patch_mode_preserves_target_file_path(tmp_path):
    patch = tmp_path / "addition.diff"
    patch.write_text(
        "\n".join(
            [
                "diff --git a/src/settings.py b/src/settings.py",
                "index 1111111..2222222 100644",
                "--- a/src/settings.py",
                "+++ b/src/settings.py",
                "@@ -0,0 +1 @@",
                f'+AWS_ACCESS_KEY_ID = "{_FAKE_AWS}"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan-file", "--patch-mode", str(patch)])

    assert result.exit_code == 1
    assert "src/settings.py" in result.output
    assert str(patch) not in result.output
