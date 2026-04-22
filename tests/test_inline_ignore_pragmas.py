from __future__ import annotations

from pathlib import Path

from detectors.composite import CompositeDetector
from scanners.filesystem_scanner import FilesystemScanner


def _scanner() -> FilesystemScanner:
    return FilesystemScanner(CompositeDetector())


def test_python_inline_ignore_suppresses_finding(tmp_path: Path) -> None:
    p = tmp_path / "app.py"
    p.write_text('password = "supersecretpassword"  # sls:ignore\n', encoding="utf-8")

    findings = _scanner().scan_path(str(tmp_path))
    assert findings == []


def test_yaml_inline_ignore_suppresses_finding(tmp_path: Path) -> None:
    p = tmp_path / "config.yaml"
    p.write_text('api_key: "AKIAIOSFODNN7EXAMPLE" # sls:ignore\n', encoding="utf-8")

    findings = _scanner().scan_path(str(tmp_path))
    assert findings == []


def test_js_inline_ignore_suppresses_finding(tmp_path: Path) -> None:
    p = tmp_path / "index.js"
    p.write_text('const token = "ghp_123456789012345678901234567890123456"; // sls:ignore\n', encoding="utf-8")

    findings = _scanner().scan_path(str(tmp_path))
    assert findings == []
