from pathlib import Path

from click.testing import CliRunner

from secret_leak_sentinel_cli import cli


def test_scan_path_missing_policy_with_strict_mode_fails():
    runner = CliRunner()
    missing = Path("does-not-exist-policy.yml")

    result = runner.invoke(
        cli,
        [
            "scan-path",
            ".",
            "--policy",
            str(missing),
            "--strict-policy",
        ],
    )

    assert result.exit_code != 0
    assert "Policy error" in result.output
    assert "missing" in result.output.lower() or "not found" in result.output.lower()
