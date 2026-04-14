from __future__ import annotations

import sys
from pathlib import Path

from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.main import cli


_FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"


def test_scan_path_ignores_publish_bridge_by_default(tmp_path: Path) -> None:
    publish_root = tmp_path / "publish-bridge" / "results"
    publish_root.mkdir(parents=True, exist_ok=True)
    (publish_root / "request.json").write_text(
        f'AWS_ACCESS_KEY_ID = "{_FAKE_AWS}"\n',
        encoding="utf-8",
    )

    runner = CliRunner()
    output_dir = tmp_path / "out"
    result = runner.invoke(
        cli,
        ["--output-dir", str(output_dir), "scan-path", str(tmp_path)],
    )

    assert result.exit_code == 0
    assert "Secret Detection Findings" not in result.output
