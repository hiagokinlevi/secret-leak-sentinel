from __future__ import annotations

import json
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


def test_scan_file_json_output_reports_clean_file(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("print('hello')\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan-file", "--json-output", str(target)])

    payload = json.loads(result.output)

    assert result.exit_code == 0
    assert payload["scan_mode"] == "file"
    assert payload["scan_target"] == str(target)
    assert payload["total_findings"] == 0
    assert payload["findings"] == []
    assert payload["summary"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }


def test_scan_file_json_output_reports_detected_secret(tmp_path):
    target = tmp_path / "config.py"
    target.write_text(f'AWS_ACCESS_KEY_ID = "{_FAKE_AWS}"\n', encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan-file", "--json-output", str(target)])

    payload = json.loads(result.output)

    assert result.exit_code == 1
    assert payload["scan_mode"] == "file"
    assert payload["total_findings"] == 1
    assert payload["findings"][0]["file_path"] == str(target)
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][0]["detector_name"] == "aws_access_key_id"
    assert payload["findings"][0]["context_labels"] == []
    assert "Fail condition met" not in result.output


def test_scan_file_json_output_includes_context_labels(tmp_path):
    target = tmp_path / ".github" / "workflows" / "release.yml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f'AWS_ACCESS_KEY_ID = "{_FAKE_AWS}"\n', encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan-file", "--json-output", str(target)])

    payload = json.loads(result.output)

    assert result.exit_code == 1
    assert "ci_pipeline" in payload["findings"][0]["context_labels"]


def test_scan_file_json_output_patch_mode_uses_patch_findings_file_path(tmp_path):
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
    result = runner.invoke(cli, ["scan-file", "--patch-mode", "--json-output", str(patch)])

    payload = json.loads(result.output)

    assert result.exit_code == 1
    assert payload["scan_mode"] == "patch"
    assert payload["scan_target"] == str(patch)
    assert payload["findings"][0]["file_path"] == "src/settings.py"
