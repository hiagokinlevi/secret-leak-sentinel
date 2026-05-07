import re

from click.testing import CliRunner

from secret_leak_sentinel_cli import cli


def test_global_version_flag_outputs_semver_string():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])

    assert result.exit_code == 0
    output = result.output.strip()
    assert re.fullmatch(r"secret-leak-sentinel, version \d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", output)
